### <b>AWS SAM CLI Vulnerabilities (CVE-2025-3047 & CVE-2025-3048)</b>
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
This README provides a detailed analysis of two security vulnerabilities found in the AWS Serverless Application Model CLI (AWS SAM CLI) – [`CVE-2025-3047`](https://www.cve.org/CVERecord?id=CVE-2025-3047) and [`CVE-2025-3048`](https://www.cve.org/CVERecord?id=CVE-2025-3048) – along with the code-level issues and fixes. Both vulnerabilities involve improper handling of symbolic links (symlinks) during the build process using Docker containers. Each section below covers one CVE with a summary, affected code (with references to the SAM CLI source), the patch and how it resolves the issue, and guidance on remediation.

These flaws involve improper handling of symbolic links (symlinks) during the `sam build --use-container` process. Both issues affect local development environments (they do not impact deployed AWS services or resources)​, but could allow unauthorized access to files on the host machine by abusing how AWS SAM CLI processes symlinks. Upgrading AWS SAM CLI to the patched versions (<b>1.133.0+</b> for CVE-2025-3047, and <b>1.134.0+</b> for CVE-2025-3048) is strongly recommended​.

#### CVE-2025-3047 – Symlink Path Traversal in Container Build
[GHSA-px37-jpqx-97q9](https://github.com/advisories/GHSA-px37-jpqx-97q9) is a path traversal vulnerability in AWS SAM CLI <b><= v1.132.0</b> that allowed unauthorized file access on the host machine during `sam build --use-container`. When building a serverless application inside a Docker container, SAM CLI would <b>follow symlinks in the project</b> by default. An attacker who could plant a malicious symlink in the project (pointing to a sensitive host file) could leverage the elevated permissions of the Docker container to have that file mounted into the container and copied to a location accessible inside the container. In effect, this meant privileged host files (outside the project directory) could be read and exfiltrated via the build container. The issue was fixed in <b>v1.133.0</b>. (To preserve backward compatibility for legitimate cases, SAM CLI v1.133.0 introduced an opt-in flag [`--mount-symlinks`](https://aws.amazon.com/security/security-bulletins/AWS-2025-008/#:~:text=to%20access%20restricted%20files%20via,symlinks%27%20parameter) to re-enable the old behavior if needed​.)

<b>Root Cause & Affected Component:</b>  The core issue lies in how AWS SAM CLI mounts project directories and their symlinks into the Docker container used for builds. In the AWS SAM CLI code (module `samcli.local.docker.container`), prior to the fix, <b>all top-level symlinks in the project directory were automatically resolved and bind-mounted into the container</b> with the same elevated privileges as the container process. The container runs as `root` by default, so resolving and mounting a symlink pointing to a sensitive host path would give the container access to that file, which an unprivileged host user would normally not have. The vulnerable code did not sufficiently restrict which symlinks to follow/mount.

Specifically, in the function that creates Docker volume mounts for the build, the SAM CLI would <b>unconditionally treat symlinks as actual files/directories to mount</b>. The vulnerability resided in the container orchestration logic of SAM CLI, specifically in the `Container.create` method of `samcli/local/docker/container.py`. In vulnerable versions, this method always attempted to resolve and mount symlink targets from the project into the Docker container, regardless of context. The problematic code is shown below, from SAM CLI v1.132.0:

```python
# samcli/local/docker/container.py (v1.132.0 - vulnerable snippet)
if self._host_dir:
    mount_mode = "rw,delegated" if self._mount_with_write else "ro,delegated"
    LOG.info("Mounting %s as %s:%s, inside runtime container", self._host_dir, self._working_dir, mount_mode)
_volumes = {
    self._host_dir: {
        "bind": self._working_dir,
        "mode": mount_mode,
    },
    **self._create_mapped_symlink_files(),  # Always resolve and mount symlinks (vulnerable) 
}
```

In the above code, `_create_mapped_symlink_files()` scans for symlinks under the project directory and prepares them to be mounted. Because this was unconditionally included, all symlinks (including those pointing outside the project) would be mounted into the container​. (see [aws/aws-sam-cli#7865](https://github.com/aws/aws-sam-cli/pull/7865/commits/6c8b7c41015daaed450e9a12a7166a5bc483c1f3#diff-89004c015f06af81ec7bf99d97b6827403738d2df8a288d05459b37706edfcca#:~:text=_volumes%20%3D%20,mapped_symlinks%2C))

The flaw here is that during a `sam build --use-container`, SAM CLI treats symlinks as files to mount into the container. If a symlink pointed to, say, `/etc/shadow` on the host, the Docker container (which might run with elevated privileges) would bind-mount that file. This is a classic <i>symlink-based path traversal</i>, resulting in <b>privilege escalation</b> – host files that the user would normally have no access to could be read by the container and then end up in build output.

<b>Patch (Fixed Code in v1.133.0):</b> The fix introduces a notion of build context and disables symlink resolution during container builds. In the patched version, `Container.create` takes an extra parameter indicating context (`BUILD` vs `INVOKE`), and it will only resolve symlinks if the context is invocation (when running functions locally), not during builds. Below is the corrected code from the patched version:

```python
# samcli/local/docker/container.py (v1.133.0+ - patched snippet)
if self._host_dir:
    mount_mode = "rw,delegated" if self._mount_with_write else "ro,delegated"
    LOG.info("Mounting %s as %s:%s, inside runtime container", self._host_dir, self._working_dir, mount_mode)
    mapped_symlinks = self._create_mapped_symlink_files() if self._resolve_symlinks(context) else {} 
_volumes = {
    self._host_dir: {
        "bind": self._working_dir,
        "mode": mount_mode,
    },
    **mapped_symlinks,  # Only mount symlinks if explicitly allowed by context (not in build) 
}
```

<i>In the patched code, `_create_mapped_symlink_files()` is wrapped behind a context check. The new `ContainerContext` enum defines contexts like `BUILD` and `INVOKE`, and `_resolve_symlinks(context)` returns False for build context​. Thus, `mapped_symlinks` will be an empty dict during builds, meaning <b>no symlinks are mounted into the container</b> by default.</i>

<b>Code Change Reference:</b> The fix was implemented in [Pull Request#7865](https://github.com/aws/aws-sam-cli/pull/7865) (<b>“fix: Resolve symlinks on local invoke only”</b>) and released as part of v1.133.0. The GitHub diff shows the introduction of the `ContainerContext` and the conditional mounting logic. By not mounting symlink targets during build, the container no longer gains access to files outside the project directory. (If a user does want to allow symlinks to host paths, they must now opt in via the `--mount-symlinks` flag​, which was added following this fix.)

<b>How the Patch Resolves the Issue:</b> After the patch, any symlinks in the project will <b>no longer be followed during the build phase</b>. They’ll simply remain as symlinks in the container (pointing to paths that won’t be mounted) or be ignored, rather than being replaced by the contents of their target. This closes the hole where an attacker could trick the build process into copying sensitive host files. In short, the build container’s view is now confined to the project directory itself (plus explicitly allowed volumes), eliminating the unintended privilege escalation.

<b>Remediation:</b> All users should upgrade to <b>AWS SAM CLI v1.133.0</b> or later to get this fix. After upgrading, the default behavior is safe. Only if you explicitly trust your project and need the old behavior should you use `sam build --use-container --mount-symlinks`. For most developers, leaving this flag off (the default) is recommended to ensure that symlinks cannot traverse outside the workspace. It’s also good practice to review any symlinks in your projects to ensure they do not point to sensitive locations.

#### CVE-2025-3048 – Symlink Path Traversal in Container Build
[GHSA-pp64-wj43-xqcr​](https://github.com/advisories/GHSA-pp64-wj43-xqcr) is a related vulnerability affecting AWS SAM CLI <b><= v1.133.0</b> (fixed in v1.134.0). A vulnerability in AWS SAM CLI’s <b>build artifact caching</b> could allow sensitive files to leak from the container back to the host workspace after a build. If a project included symlinks, after running `sam build --use-container`, the <b>contents of the symlink targets would be copied into the local build cache directory</b> as regular files or folders​. In effect, a developer without access to certain host files could gain access because those files’ contents end up in the `.aws-sam` build output on the host. For example, a symlink in the project pointing to `/secret/config` could result in the actual content of `/secret/config` appearing in the project’s `.aws-sam/build` folder after the container build, even if the user couldn’t read `/secret/config` directly.

<b>Root Cause & Affected Component:</b> The core of this issue was in how SAM CLI copied files out of the container (or from the build process) into the local project’s build artifacts directory. The function responsible for file copying is found in `samcli/lib/utils/osutils.py`, specifically the custom `copytree` utility. In vulnerable versions, this function used Python’s `shutil.copy2` without specifying `follow_symlinks=False`, which by default <b>follows symlinks</b> and copies the file contents. The snippet below (from v1.133.0) shows the problematic logic:

```python
# samcli/lib/utils/osutils.py (v1.133.0 - vulnerable snippet)
# ... inside osutils.copytree ...
else:
    try:
        shutil.copy2(new_source, new_destination)  # follow_symlinks is True by default (vulnerable)
    except OSError as e:
        if e.errno != errno.EINVAL:
            raise e
```

<i>Here, if `new_source` is a symlink, `shutil.copy2` will resolve the symlink and copy the target file to `new_destination`. There was no flag to tell it to preserve the symlink. Thus, a symlink to a sensitive file would result in that file’s <b>contents</b> appearing in the destination directory.</i> (see aws/aws-sam-cli#7890)

In practical terms, imagine the build process created a symlink `config -> /etc/secret-config` (perhaps as part of layering dependencies or as left over from CVE-2025-3047’s scenario). The above code would copy the contents of `/etc/secret-config` into the local build output as `config`. A local user who couldn’t read `/etc/secret-config` directly could now simply open the file under `.aws-sam/build/.../config` and see its contents.

<b>Patch (Fixed Code in v1.134.0):</b> The fix was straightforward – preserve symlinks instead of following them when copying. In Python’s shutil, this is done by passing `follow_symlinks=False`. The patched code (v1.134.0) changes the copy call as follows:

```python
# samcli/lib/utils/osutils.py (v1.134.0 - patched snippet)
else:
    try:
        shutil.copy2(new_source, new_destination, follow_symlinks=False)  # Do not follow symlinks (fixed)
    except OSError as e:
        if e.errno != errno.EINVAL:
            raise e
```

<i>With` follow_symlinks=Fals`e, if `new_source` is a symlink, the function will copy the symlink itself [rather than the file it points to](https://github.com/aws/aws-sam-cli/pull/7890/commits/af13758eb74a72bc0702229d6cfc7e5744520d99)​. In other words, the build output will contain a symlink with the same target, instead of a real file with the target’s contents.</i>

<b>Code Change Reference:</b> The change was made in [Pull Request#7890](https://github.com/aws/aws-sam-cli/pull/7980) (<b>“fix: Keep symlinks when copying files after build”</b>) and released in v1.134.0. The GitHub diff of this PR confirms the addition of the `follow_symlinks=False` parameter to `shutil.copy2`, [along with updated unit tests to ensure symlinks are preserved](https://github.com/aws/aws-sam-cli/pull/7890/commits/af13758eb74a72bc0702229d6cfc7e5744520d99#:~:text=patched_os,follow_symlinks%3DFalse). The PR description explicitly notes: <i>“Symlinks will stop being transformed into copies of the files and keep their symlink status.”​</i> This means the build artifacts will contain symlinks (which reference the original file paths) instead of unauthorized copies of the file data.

<b>How the Patch Resolves the Issue:</b> After this fix, the SAM CLI’s post-build file copying no longer leaks file contents. If a symlink was created during build, it will remain a symlink in the output. The local user won’t magically gain read access to the target’s content – they’ll just see a symlink that still points to the original path. Unless the user already had permission to read the target file, the symlink in the output is harmless (it will error out if dereferenced without proper access). Essentially, <B>the confidentiality impact is mitigated</b>: sensitive files aren’t inadvertently materialized into the user’s workspace​. This fix complements the CVE-2025-3047 patch: it stopped the container from grabbing host files via symlinks; the fix for CVE-2025-3048 stops any that <i>did</i> get through (or existed legitimately) from being persisted as plain files in the output.

<b>Remediation:</b> Users should upgrade to <b>AWS SAM CLI v1.134.0</b> or newer to obtain [this patch](https://github.com/advisories/GHSA-pp64-wj43-xqcr#:~:text=Patches). Once on v1.134.0+, the build process will preserve symlinks by default, fixing this vulnerability. After upgrading, it’s recommended to clean and rebuild any SAM applications to ensure that any cached build artifacts are regenerated under the new safer behavior​ (the AWS security bulletin advises running a fresh `sam build --use-container` after upgrading). There are no workarounds for this issue in older versions besides manually removing sensitive symlinks or not using container builds, so upgrading is the only robust solution. In general, treat the local SAM CLI build folder as sensitive output – with the patch it should no longer contain unexpected secrets, but it’s good practice to keep an eye on what ends up in your build artifacts.


<b>References:</b>
- [AWS Security Bulletin AWS-2025-008](https://aws.amazon.com/security/security-bulletins/AWS-2025-008/) – <i>Issue with AWS SAM CLI (CVE-2025-3047, CVE-2025-3048)</i>
- [GitHub Advisory Database entries for CVE-2025-3047](https://github.com/advisories/GHSA-px37-jpqx-97q9)
- [GitHub Advisory Database entries for CVE-2025-3048](https://github.com/advisories/GHSA-pp64-wj43-xqcr)

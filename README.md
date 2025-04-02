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

#### CVE-2025-3047 – Symlink Path Traversal in Container Build


<b>Root Cause & Affected Component:</b> 
<b>Patch (Fixed Code in v1.134.0):</b>
<b>Code Change Reference:</b>
<b>How the Patch Resolves the Issue:</b>
<b>Remediation</b>

<b>References:</b>
- [AWS Security Bulletin AWS-2025-008](https://aws.amazon.com/security/security-bulletins/AWS-2025-008/) – <i>Issue with AWS SAM CLI (CVE-2025-3047, CVE-2025-3048</i>
- [GitHub Advisory Database entries for CVE-2025-3047](https://github.com/advisories/GHSA-px37-jpqx-97q9)
- [GitHub Advisory Database entries for CVE-2025-3048](https://github.com/advisories/GHSA-pp64-wj43-xqcr)

# Rsync Trigger

Watches a folder and syncs it to a remote machine using `rsync` whenever changes are detected. Useful for rapid deployment, live testing environments, or syncing infra/playbooks during red team operations.

```text
Rsync Trigger

Usage: ./rsync_trigger.sh <folder-to-watch> <host>
```

## Running the Sync Tool
SSH must be configured (e.g., using `~/.ssh/config`). You can authenticate using either your SSH key or a password via sshpass.

```bash
./rsync_trigger.sh playbook my_server
```

Alternatively you can provide a password.

```bash
PASSWORD=mypassword ./rsync_trigger.sh playbook my_server
```

## SSH Config Example

Set up your `~/.ssh/config` like this:

```text
Host my_server
    HostName 10.10.110.18
    User mitchel
    IdentityFile ~/.ssh/id_rsa
```

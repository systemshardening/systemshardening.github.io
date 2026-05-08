---
title: "Linux SCADA/HMI Workstation Hardening: Operator Stations in OT Zero Trust"
description: "CISA's OT Zero Trust guidance targets Living Off The Land attacks on HMI workstations. Harden Linux SCADA displays with kiosk lockdown, application allowlisting around vendor software, and EDR without disrupting control system I/O."
slug: linux-ot-hmi-hardening
date: 2026-05-03
lastmod: 2026-05-03
category: linux
tags:
  - ot-security
  - hmi
  - scada
  - application-control
  - ics
personas:
  - platform-engineer
  - security-engineer
article_number: 407
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-ot-hmi-hardening/
---

# Linux SCADA/HMI Workstation Hardening: Operator Stations in OT Zero Trust

## The Problem

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" identifies HMI workstations as one of the two most common lateral movement targets in OT networks — the other being historians. Volt Typhoon and comparable nation-state actors establish initial access on HMI workstations because they occupy a structurally privileged position: they have IT network connectivity for software updates and direct OPC-UA or serial connections to PLCs. That combination makes them the most efficient pivot point in the OT architecture.

The Living Off The Land pattern on HMI workstations is specific. Attackers use `python3`, `curl`, vendor engineering software command-line interfaces, and bash scripts that invoke Ignition gateway APIs — tooling that is already installed, trusted by the operating system, and indistinguishable from normal operator workflow if execution is not monitored. CISA's advisory documents this pattern across multiple critical infrastructure incidents: no novel malware was needed, only the tools the SCADA vendor shipped.

The hardening challenge that makes HMI workstations harder to lock down than jump hosts is the vendor software stack itself. Wonderware InTouch requires Python libraries in the system path. GE iFIX requires a local SQL Server equivalent and expects broad read-write access to the `/opt/iFIX` hierarchy. Inductive Automation Ignition runs a Java application server with a web-based HMI frontend, uses an embedded H2 database, and opens OPC-UA port 4840. Custom I/O card drivers for serial-to-process interfaces load proprietary kernel modules that must remain loadable after boot. None of these constraints exist on a minimal jump host. Stripping the SCADA workstation to a jump host configuration breaks the control system; applying no controls at all leaves the most networked host in the OT environment unprotected.

The hardening goal is precisely scoped: reduce the LOTL attack surface to the minimum required by the SCADA vendor while preserving every function the control system depends on. That requires documenting the vendor's actual requirements before applying any control — not after it breaks something in production.

**Target systems:** Ubuntu 22.04 LTS / 24.04 LTS (Wonderware, Ignition), RHEL 9 / Rocky Linux 9 (GE iFIX, OSIsoft PI). Examples note where behaviour differs between distributions.

## Threat Model

- **LOTL attacks using vendor-installed tools:** Python runtimes, OPC toolkits, browser-based HMI engines, and Ignition gateway CLI scripts are legitimate components of the SCADA stack. An attacker who gains code execution on the HMI workstation can use these tools for reconnaissance, lateral movement, and data exfiltration without triggering signature-based detections. The CISA advisory names this as the primary exploitation pattern on HMI hosts.
- **Compromised SCADA vendor update mechanism:** Vendor software updates for Wonderware, Ignition, and iFIX are typically delivered over an IT network path — either a direct internet connection or a software distribution server in the IT DMZ. A supply chain compromise that delivers a malicious update package propagates to every HMI workstation in the fleet simultaneously, bypassing all host-based controls that only examine running state.
- **HMI workstation as a pivot point:** The workstation is dual-homed — OT-side via OPC-UA to PLCs and serial connections to field devices, IT-side via the historian sync path. An attacker who establishes persistence on the HMI workstation has bidirectional network access to both environments. This is the structural reason CISA identifies HMI hosts alongside historians as priority lateral movement targets.
- **Privilege escalation via SCADA software running as root:** Legacy installations of Wonderware InTouch and GE iFIX commonly run as root because they were installed without a service account and their documentation did not historically require one. A process running as root with OPC-UA network access and a Python runtime available is close to an unrestricted attack platform.
- **Physical access to an unlocked HMI console:** Operator stations are left logged in and displaying live process data — that is their function. An unlocked console with a visible keyboard gives a visitor with brief physical access a fully authenticated session in the SCADA application context. Without kiosk lockdown, that session also gives access to a terminal emulator, a file manager, and a browser.

## Hardening Configuration

### 1. Vendor Software Inventory Before Lockdown

No control should be applied before the vendor software stack is fully documented. AppArmor profiles built from incomplete knowledge deny legitimate access and break the control system. This step is not optional — it is the prerequisite for every subsequent step.

Capture the listening network state of the SCADA application during normal operations:

```bash
ss -tulpn
```

Capture loaded kernel modules:

```bash
lsmod | sort > /tmp/hmi-baseline-modules.txt
```

Enumerate binaries in vendor installation directories:

```bash
find /opt/wonderware /opt/ignition /opt/iFIX -type f -executable 2>/dev/null \
  | sort > /tmp/hmi-baseline-executables.txt
```

Enumerate device nodes the SCADA application accesses (capture during a full process poll cycle):

```bash
lsof -p $(pgrep -f "wonderware|ignition|ifix") 2>/dev/null \
  | grep -E "^.*(REG|CHR|BLK)" \
  | awk '{print $NF}' | sort -u > /tmp/hmi-baseline-files.txt
```

Capture active network connections from the SCADA process:

```bash
ss -tulpn -e | grep -E "ignition|wonderware|ifix" > /tmp/hmi-baseline-network.txt
```

Store these baseline files under version control. They become the authoritative reference for AppArmor profile construction and `fapolicyd` rule writing, and they document the pre-hardening state for change management.

### 2. AppArmor Confined SCADA Profile

AppArmor is the correct primary confinement mechanism for Ubuntu-based HMI workstations. It operates at the path level — well matched to the specific file hierarchy, device nodes, and network ports the SCADA vendor documents — without requiring the policy language depth of SELinux.

Build an initial profile in complain (permissive) mode using the audit log:

```bash
aa-genprof /opt/ignition/ignition-gateway
```

After two to four weeks of normal operations in complain mode, refine the profile with logged access events:

```bash
aa-logprof
```

The refined profile skeleton for an Inductive Automation Ignition installation:

```
/etc/apparmor.d/opt.ignition.ignition-gateway

#include <tunables/global>

/opt/ignition/ignition-gateway {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/java>

  /opt/ignition/ r,
  /opt/ignition/** rw,

  /var/lib/ignition/ rw,
  /var/lib/ignition/** rw,

  /var/log/ignition/ rw,
  /var/log/ignition/** w,

  /tmp/ignition-* rw,

  /dev/ttyS* rw,
  /dev/ttyUSB* rw,
  /dev/usbserial* rw,

  network inet stream,
  network inet6 stream,

  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/nsswitch.conf r,

  /proc/*/fd/ r,
  /proc/*/status r,

  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /bin/bash x,
  deny /usr/bin/python3 x,
  deny /usr/bin/nc x,
}
```

The critical entries are the explicit `deny` rules for general-purpose tools. AppArmor's deny-by-default means these are redundant for paths not explicitly allowed, but writing them explicitly documents the LOTL surface being closed and causes an explicit DENIED log entry rather than a silent implicit denial — useful for SIEM detection rules.

Load in complain mode initially:

```bash
apparmor_parser -r -C /etc/apparmor.d/opt.ignition.ignition-gateway
aa-complain /etc/apparmor.d/opt.ignition.ignition-gateway
```

Switch to enforce after audit period:

```bash
aa-enforce /etc/apparmor.d/opt.ignition.ignition-gateway
```

### 3. `fapolicyd` Allowlist Scoped to Vendor Paths

On RHEL 9 / Rocky Linux 9, `fapolicyd` provides execution control that complements SELinux and operates at the binary trust level. Configure it with rules that permit binaries in the vendor installation directory while blocking general-purpose tooling — including Python interpreters invoked outside vendor paths.

```bash
dnf install fapolicyd
systemctl enable --now fapolicyd
```

Write a dedicated rules file for the HMI workstation role:

```conf
/etc/fapolicyd/rules.d/90-hmi-scada.rules

allow perm=execute exe=/opt/iFIX/ : all
allow perm=execute exe=/opt/iFIX/bin/ : all
allow perm=execute exe=/opt/iFIX/bin/ifix : all
allow perm=execute exe=/opt/iFIX/python/bin/python3 : all

allow perm=execute exe=/usr/bin/bash : all
allow perm=execute exe=/usr/bin/sh : all
allow perm=execute exe=/usr/lib/systemd/systemd : all
allow perm=execute exe=/usr/bin/dbus-daemon : all

deny perm=execute exe=/usr/bin/python3 : all
deny perm=execute exe=/usr/bin/curl : all
deny perm=execute exe=/usr/bin/wget : all
deny perm=execute exe=/usr/bin/nc : all
deny perm=execute exe=/usr/bin/ncat : all

deny perm=execute all : all
```

The key distinction from a jump host allowlist is the vendor Python path. GE iFIX and Ignition both ship embedded Python runtimes under their installation directories; those paths are allowed. The system Python at `/usr/bin/python3` — the tool an attacker would use — is explicitly denied. A LOTL attack that invokes `python3` from the operator shell gets `Operation not permitted` from the kernel before any interpreter bytecode executes.

Rebuild the trust database and reload after every rule change:

```bash
fapolicyd-cli --update
systemctl restart fapolicyd
```

### 4. Kiosk-Mode Desktop Lockdown

The SCADA workstation display should present only the SCADA application. An operator should not be able to open a terminal, a file manager, or a browser from the desktop. The mechanism on a GNOME-based system is a combination of GDM autologin to a restricted session and `dconf` settings that disable every interactive desktop feature.

Configure GDM autologin for the SCADA operator account:

```ini
/etc/gdm3/custom.conf

[daemon]
AutomaticLoginEnable=True
AutomaticLogin=scada-operator
TimedLoginEnable=False
```

Lock down the GNOME session using `dconf` machine-level defaults. Create a database file and a locks file:

```bash
mkdir -p /etc/dconf/db/hmi.d/locks
```

```ini
/etc/dconf/db/hmi.d/00-hmi-lockdown

[org/gnome/desktop/lockdown]
disable-application-handlers=true
disable-command-line=true
disable-lock-screen=false
disable-printing=true
disable-print-setup=true
disable-user-switching=true

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 300

[org/gnome/shell]
enabled-extensions=[]
favorite-apps=[]

[org/gnome/desktop/interface]
enable-animations=false

[org/gnome/settings-daemon/plugins/media-keys]
custom-keybindings=[]
terminal=''
```

```ini
/etc/dconf/db/hmi.d/locks/00-hmi-lockdown

/org/gnome/desktop/lockdown/disable-command-line
/org/gnome/desktop/lockdown/disable-application-handlers
/org/gnome/desktop/lockdown/disable-user-switching
/org/gnome/shell/enabled-extensions
/org/gnome/settings-daemon/plugins/media-keys/terminal
```

Apply the dconf database:

```bash
dconf update
```

Add the custom database to the dconf profile:

```ini
/etc/dconf/profile/user

user-db:user
system-db:hmi
```

Configure the SCADA operator session to launch the application directly via an autostart file that also prevents the desktop from appearing:

```ini
/home/scada-operator/.config/autostart/ignition-hmi.desktop

[Desktop Entry]
Type=Application
Name=Ignition HMI
Exec=/opt/ignition/ignition-gateway --start-client
X-GNOME-Autostart-enabled=true
NoDisplay=false
```

Disable virtual terminal switching at the console level by overriding the keyboard shortcut in the X configuration:

```conf
/etc/X11/xorg.conf.d/90-disable-vt-switch.conf

Section "ServerFlags"
    Option "DontVTSwitch" "true"
EndSection
```

This configuration closes the Ctrl+Alt+F2 path that would give an attacker physical console access to a virtual terminal while the graphical session remains running.

### 5. SCADA Service User Least Privilege

A SCADA process running as root is the most common single control failure in legacy HMI installations. The service account isolation change is low-risk to implement and high-value: it limits the damage from any code execution to what the service account can reach.

Create the service account:

```bash
useradd -r -s /sbin/nologin -d /opt/ignition -c "Ignition SCADA service" ignition-svc
chown -R ignition-svc:ignition-svc /opt/ignition /var/lib/ignition /var/log/ignition
```

Assign only the capabilities the process requires. `CAP_NET_BIND_SERVICE` is needed if the SCADA service binds to a privileged port (OPC-UA uses 4840, which does not require it, but some vendor configurations bind to port 443). `CAP_SYS_RAWIO` is required for direct hardware I/O card access. Add `CAP_DAC_OVERRIDE` only if the vendor explicitly requires it — it is broad and should be avoided if a file permission fix resolves the underlying issue.

```ini
/etc/systemd/system/ignition-gateway.service

[Unit]
Description=Inductive Automation Ignition Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=ignition-svc
Group=ignition-svc
ExecStart=/opt/ignition/ignition-gateway start
ExecStop=/opt/ignition/ignition-gateway stop
PIDFile=/var/run/ignition/ignition.pid

CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_RAWIO
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_RAWIO
NoNewPrivileges=yes

ProtectSystem=strict
ReadWritePaths=/opt/ignition /var/lib/ignition /var/log/ignition /tmp
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

SupplementaryGroups=dialout

[Install]
WantedBy=multi-user.target
```

The `dialout` supplementary group provides access to `/dev/ttyS*` and `/dev/ttyUSB*` serial device nodes without requiring `CAP_SYS_RAWIO` for serial access specifically. Use the group membership for serial access and keep `CAP_SYS_RAWIO` only if a hardware I/O card genuinely requires raw I/O — verify this with the vendor before adding the capability.

Reload and restart:

```bash
systemctl daemon-reload
systemctl restart ignition-gateway.service
```

### 6. EDR Placement

The AppArmor and `fapolicyd` controls block known LOTL tooling. EDR with behavioural analysis detects LOTL patterns that exploit the vendor tooling itself — an attacker who uses the Ignition gateway scripting API to execute system commands stays within the allowed execution paths but spawns unexpected child processes from the SCADA parent.

Deploy the Wazuh agent, configured to monitor the SCADA process tree:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install wazuh-agent
```

Configure the Wazuh agent to submit process creation events with parent process context:

```xml
/var/ossec/etc/ossec.conf (agent section)

<syscheck>
  <directories realtime="yes" report_changes="yes">/opt/ignition/data</directories>
  <directories realtime="yes">/etc/apparmor.d</directories>
  <directories realtime="yes">/etc/fapolicyd</directories>
</syscheck>

<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

On the Wazuh manager, add a detection rule for unexpected process spawning from a SCADA parent:

```xml
/var/ossec/etc/rules/local_rules.xml

<group name="scada,lotl,">

  <rule id="100200" level="12">
    <if_group>audit_command</if_group>
    <field name="audit.ppid" type="pcre2">
      (?:ignition-gateway|wonderware|ifix|lcad|aaHistorian)
    </field>
    <field name="audit.exe" type="pcre2">
      (?:/usr/bin/python3|/usr/bin/curl|/usr/bin/wget|/bin/bash|/usr/bin/nc|/usr/bin/ncat)
    </field>
    <description>SCADA process spawned a suspicious child process - possible LOTL attack</description>
    <mitre>
      <id>T1059</id>
      <id>T1218</id>
    </mitre>
  </rule>

  <rule id="100201" level="10">
    <if_group>audit_command</if_group>
    <field name="audit.ppid" type="pcre2">
      (?:ignition-gateway|wonderware|ifix)
    </field>
    <field name="audit.exe" type="pcre2">^/opt/(?!ignition|wonderware|iFIX)</field>
    <description>SCADA process spawned binary outside vendor directory</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>

</group>
```

Rule 100200 fires when a known SCADA parent process spawns a well-known LOTL tool. Rule 100201 catches execution of any binary outside the vendor directories from a SCADA parent — a broader catch for novel paths. Both rules should generate immediate alerts; level 12 in Wazuh maps to critical.

## Expected Behaviour After Hardening

After AppArmor enforcement is active: the Ignition gateway runs normally, processes live data, and renders the HMI client. An attempt to open a terminal from within the SCADA process context — for example, a command injection through a misconfigured gateway script — is denied. The kernel logs the denial:

```
kernel: audit: type=1400 audit(1746316800.123:42): apparmor="DENIED" operation="exec"
  profile="/opt/ignition/ignition-gateway" name="/usr/bin/bash"
  pid=3812 comm="ignition-gatewa" requested_mask="x" denied_mask="x"
```

After `fapolicyd` is in enforce mode: running `curl https://example.com` from the operator console returns an error before any network connection is attempted:

```bash
bash: /usr/bin/curl: Operation not permitted
```

After kiosk lockdown: pressing Ctrl+Alt+T produces no terminal window. Right-clicking on the desktop shows no context menu. Ctrl+Alt+F2 does not switch to a virtual terminal — the X server ignores the VT switch request due to the `DontVTSwitch` option. The screen shows only the SCADA application.

After service account migration: `ps aux | grep ignition` shows the gateway process running as `ignition-svc`, not `root`. Attempting to read `/etc/shadow` from within the process context returns `Permission denied` even if the file descriptor is opened through a vendor scripting API.

## Trade-offs and Operational Considerations

**AppArmor profile must be built from a complete audit log.** The audit period in complain mode should cover at least one complete production cycle — for a plant that has weekly maintenance windows with different SCADA workflows, two to four weeks is the minimum. A profile built from a partial operational sample will deny access that only occurs during maintenance or shift handover, causing the first enforce-mode deployment to fail at an operationally inconvenient moment. Collect audit data in a staging environment that mirrors the production SCADA configuration before applying to production.

**`fapolicyd` rules require updating on every SCADA vendor software update.** When Inductive Automation releases an Ignition update that changes the path of an internal executable, or when a Wonderware patch adds a new binary to the installation, `fapolicyd` blocks it until the trust database is rebuilt. This is not a flaw in the control — it is the control working correctly — but it requires a documented change-control process. Every vendor software update must include a step that validates `fapolicyd` rules against the new binary paths before the update is applied in production.

**Kiosk lockdown requires a documented break-glass process for legitimate non-SCADA tasks.** Operators occasionally need to access a vendor documentation PDF, complete an online training module, or use a remote desktop client for a supplemental system. These tasks are impossible in kiosk mode. The break-glass process should define: who can authorise temporarily lifting kiosk restrictions, what the method is (a separate administrator session or a dedicated non-kiosk account), and how that access is logged. The break-glass account itself should be subject to session recording.

**EDR agent resource consumption must be validated before production deployment.** Wazuh's file integrity monitoring and audit log forwarding add CPU and I/O overhead. On a workstation polling PLCs at 100ms intervals, unexpectedly high CPU load from the EDR agent can affect scan cycle timing. Test the agent under a load profile that matches peak production polling rates — typically achieved by running a full process historian capture while simultaneously exercising all connected PLC addresses. Validate that scan cycle jitter remains within the SCADA vendor's specified tolerance.

## Failure Modes

**AppArmor profile built in permissive mode that is never switched to enforce.** Teams that run complain mode without a scheduled enforcement date accumulate audit log data indefinitely and delay the actual control. The AppArmor deny rules provide no protection in complain mode — violations are logged but allowed. Establish a target enforcement date at the start of the audit period. If the profile is not ready by that date, investigate why rather than extending indefinitely.

**SCADA vendor update applies over allowlisted binary paths, breaking `fapolicyd` rules.** A vendor update that replaces or relocates binaries will cause the SCADA application to fail to start on the next restart, not during the update itself. Operations teams who do not connect the update event to the startup failure waste time in the wrong diagnostic path. Mitigate by running `fapolicyd-cli --list` against the new installation before restarting the service, and by including `fapolicyd` rule review as a required step in the vendor update procedure.

**Kiosk lockdown applied to the graphical session but not to the local console.** The `DontVTSwitch` X configuration and `dconf` lockdown apply within the graphical session. An attacker with physical access who powers off and reboots the workstation, or accesses the out-of-band management console, encounters a standard login prompt with no kiosk restrictions. Apply the same terminal lockdown controls to the physical console by restricting `getty` sessions and ensuring that the GRUB configuration does not permit single-user mode access without a password.

**EDR agent excluded from monitoring the SCADA process tree to avoid performance impact.** The most consequential place to detect a LOTL attack on an HMI workstation is in the SCADA process tree — that is where attacker activity occurs. An EDR configuration that excludes the SCADA process from monitoring eliminates the detection coverage the control is designed to provide. If the agent causes performance issues under the SCADA process, the correct response is to tune the agent's monitoring frequency or increase the workstation hardware resources, not to exclude the process from monitoring.

## Related Articles

- [Linux OT Jump Host Hardening](/articles/linux/linux-ot-jump-host-hardening/)
- [AppArmor](/articles/linux/apparmor/)
- [Systemd Unit Hardening](/articles/linux/systemd-unit-hardening/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)

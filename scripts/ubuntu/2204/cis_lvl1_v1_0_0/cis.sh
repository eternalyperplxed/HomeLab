#!/usr/bin/env bash

#This script is intended for an Ubuntu Cloud image and makes the needed changes to comply with CIS Level 1 v1.0.0 settings.
killall apt-get
#CIS 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if LC_ALL=C grep -q -m 1 "^install cramfs" /etc/modprobe.d/cramfs.conf ; then
	
	sed -i 's#^install cramfs.*#install cramfs /bin/true#g' /etc/modprobe.d/cramfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/cramfs.conf
	echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.1.2.3 - Ensure noexec option is set on /tmp partition
if ( [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && findmnt --kernel "/tmp" > /dev/null || findmnt --fstab "/tmp" > /dev/null ); then
function perform_remediation {    
        mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" "/tmp")"
    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /tmp in /etc/fstab" >&2; return 1; }
    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /tmp)"
    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo " /tmp  defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi
    if mkdir -p "/tmp"; then
        if mountpoint -q "/tmp"; then
            mount -o remount --target "/tmp"
        fi
    fi
}
perform_remediation
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.1.10 - Disable USB Storage Driver
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	
	sed -i 's#^install usb-storage.*#install usb-storage /bin/true#g' /etc/modprobe.d/usb-storage.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.1.8.1 - Ensure nodev option set on /dev/shm partition
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
function perform_remediation {
    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"
    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi
    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}
perform_remediation
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.1.8.2 - Ensure noexec option set on /dev/shm partition
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
function perform_remediation {
    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi
    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}
perform_remediation
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.1.8.3 - Ensure nosuid option set on /dev/shm partition
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
function perform_remediation {
    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi
    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}
perform_remediation
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.3.1 - Ensure AIDE is installed
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"
AIDE_CONFIG=/etc/aide/aide.conf
DEFAULT_DB_PATH=/var/lib/aide/aide.db
# Fix db path in the config file, if necessary
if ! grep -q '^database=file:' ${AIDE_CONFIG}; then
    # replace_or_append gets confused by 'database=file' as a key, so should not be used.
    #replace_or_append "${AIDE_CONFIG}" '^database=file' "${DEFAULT_DB_PATH}" '@CCENUM@' '%s:%s'
    echo "database=file:${DEFAULT_DB_PATH}" >> ${AIDE_CONFIG}
fi
# Fix db out path in the config file, if necessary
if ! grep -q '^database_out=file:' ${AIDE_CONFIG}; then
    echo "database_out=file:${DEFAULT_DB_PATH}.new" >> ${AIDE_CONFIG}
fi
/usr/sbin/aideinit -y -f
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.4.2 - Ensure permissions on bootloader config are configured
# Remediation is applicable only in certain platforms
if [ ! -d /sys/firmware/efi ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then
chmod u-xs,g-xwrs,o-xwrt /boot/grub/grub.cfg
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.5.1 - Ensure address space layout randomization (ASLR) is enabled
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of kernel.randomize_va_space from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.randomize_va_space.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.randomize_va_space" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
# Set sysctl config file which to save the desired value
SYSCONFIG_FILE="/etc/sysctl.conf"
# Set runtime for kernel.randomize_va_space
/sbin/sysctl -q -n -w kernel.randomize_va_space="2"
# If kernel.randomize_va_space present in /etc/sysctl.conf, change value to "2"
#	else, add "kernel.randomize_va_space = 2" to /etc/sysctl.conf
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^kernel.randomize_va_space")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "2"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^kernel.randomize_va_space\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^kernel.randomize_va_space\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.5.3 - Ensure Automatic Error Reporting is not enabled
SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'apport.service'
"$SYSTEMCTL_EXEC" disable 'apport.service'
"$SYSTEMCTL_EXEC" mask 'apport.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files apport.socket; then
    "$SYSTEMCTL_EXEC" stop 'apport.socket'
    "$SYSTEMCTL_EXEC" mask 'apport.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'apport.service' || true

#CIS 1.5.4 - Ensure core dumps are restricted
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
SECURITY_LIMITS_FILE="/etc/security/limits.conf"
if grep -qE '^\s*\*\s+hard\s+core' $SECURITY_LIMITS_FILE; then
        sed -ri 's/(hard\s+core\s+)[[:digit:]]+/\1 0/' $SECURITY_LIMITS_FILE
else
        echo "*     hard   core    0" >> $SECURITY_LIMITS_FILE
fi
if ls /etc/security/limits.d/*.conf > /dev/null; then
        sed -ri '/^\s*\*\s+hard\s+core/d' /etc/security/limits.d/*.conf
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of fs.suid_dumpable from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*fs.suid_dumpable.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "fs.suid_dumpable" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
#
# Set runtime for fs.suid_dumpable
#
/sbin/sysctl -q -n -w fs.suid_dumpable="0"
#
# If fs.suid_dumpable present in /etc/sysctl.conf, change value to "0"
#	else, add "fs.suid_dumpable = 0" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^fs.suid_dumpable")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^fs.suid_dumpable\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^fs.suid_dumpable\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.6.1.1 - Ensure AppArmor is installed
apt install -y apparmor apparmor-utils

#CIS 1.6.1.2 - Ensure AppArmor is enabled in the bootloader configuration
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*apparmor=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an apparmor= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)apparmor=[^[:space:]]\+\(.*\"\)/\1apparmor=1\2/"  '/etc/default/grub'
else
       # no apparmor=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 apparmor=1\"/"  '/etc/default/grub'
fi
# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*security=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an security= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)security=[^[:space:]]\+\(.*\"\)/\1security=apparmor\2/"  '/etc/default/grub'
else
       # no security=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 security=apparmor\"/"  '/etc/default/grub'
fi
update-grub
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 1.6.1.3 - Ensure all AppArmor Profiles are in enforce or complain mode
aa-enforce /etc/apparmor.d/*

#CIS 1.7.1 Ensure message of the day is configured properly
[[ -f /etc/motd ]] && rm /etc/motd

#CIS 1.7.2 - Ensure local login warning banner is configured properly
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

#CIS 1.7.3 - Ensure remote login warning banner is configured properly
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

#CIS 1.7.5 - Ensure permissions on /etc/issue are configured
chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)

#CIS 1.7.6 - Ensure permissions on /etc/issue.net are configured
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)

#CIS 2.1.1.1 - Ensure a single time synchronization daemon is in use
apt purge -y chrony ntp

#CIS 2.2.15 - Ensure mail transfer agent is configured for local-only mode
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'postfix' 2>/dev/null | grep -q installed; }; then
var_postfix_inet_interfaces='loopback-only'
if [ -e "/etc/postfix/main.cf" ] ; then   
    LC_ALL=C sed -i "/^\s*inet_interfaces\s\+=\s\+/Id" "/etc/postfix/main.cf"
else
    touch "/etc/postfix/main.cf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/postfix/main.cf"
cp "/etc/postfix/main.cf" "/etc/postfix/main.cf.bak"
# Insert at the end of the file
printf '%s\n' "inet_interfaces=$var_postfix_inet_interfaces" >> "/etc/postfix/main.cf"
# Clean up after ourselves.
rm "/etc/postfix/main.cf.bak"
systemctl restart postfix
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 2.2.16 - Ensure rsync service is either not installed or masked
apt purge -y rsync

#CIS 2.3.2 - Ensure rsh client is not installed
#apt purge rsh-clent

#CIS 2.3.3 - Ensure talk client is not installed
#apt purge talk

#CIS 2.3.4 - Ensure telnet client is not installed
apt purge -y telnet

#CIS 3.2.1 - Ensure packet redirect sending is disabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.default.send_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.send_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
#
# Set runtime for net.ipv4.conf.default.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.send_redirects="0"
#
# If net.ipv4.conf.default.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.default.send_redirects = 0" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.send_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.send_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.send_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.all.send_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.send_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
#
# Set runtime for net.ipv4.conf.all.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.send_redirects="0"
#
# If net.ipv4.conf.all.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.all.send_redirects = 0" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.send_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.send_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.send_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.2.2 - Ensure IP forwarding is disabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv6.conf.all.forwarding from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.forwarding.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.forwarding" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv6_conf_all_forwarding_value='0'
#
# Set runtime for net.ipv6.conf.all.forwarding
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.forwarding="$sysctl_net_ipv6_conf_all_forwarding_value"
#
# If net.ipv6.conf.all.forwarding present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.forwarding = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.forwarding")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_forwarding_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.forwarding\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.forwarding\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.ip_forward from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.ip_forward.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.ip_forward" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
#
# Set runtime for net.ipv4.ip_forward
#
/sbin/sysctl -q -n -w net.ipv4.ip_forward="0"
#
# If net.ipv4.ip_forward present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.ip_forward = 0" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.ip_forward")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.ip_forward\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.ip_forward\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.1 - Ensure source routed packets are not accepted
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv6.conf.default.accept_source_route from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default.accept_source_route" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv6_conf_default_accept_source_route_value='0'
#
# Set runtime for net.ipv6.conf.default.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv6.conf.default.accept_source_route="$sysctl_net_ipv6_conf_default_accept_source_route_value"
#
# If net.ipv6.conf.default.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.default.accept_source_route = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.default.accept_source_route")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_default_accept_source_route_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.default.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.default.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv6.conf.all.accept_source_route from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_source_route" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv6_conf_all_accept_source_route_value='0'
#
# Set runtime for net.ipv6.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_source_route="$sysctl_net_ipv6_conf_all_accept_source_route_value"
#
# If net.ipv6.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_source_route = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_source_route")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_source_route_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.all.accept_source_route from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.accept_source_route" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_all_accept_source_route_value='0'
#
# Set runtime for net.ipv4.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_source_route="$sysctl_net_ipv4_conf_all_accept_source_route_value"
#
# If net.ipv4.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_source_route = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.accept_source_route")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_accept_source_route_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.2 - Ensure ICMP redirects are not accepted
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv6.conf.default.accept_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default.accept_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv6_conf_default_accept_redirects_value='0'
#
# Set runtime for net.ipv6.conf.default.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv6.conf.default.accept_redirects="$sysctl_net_ipv6_conf_default_accept_redirects_value"
#
# If net.ipv6.conf.default.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.default.accept_redirects = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.default.accept_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_default_accept_redirects_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.default.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.default.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.all.accept_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.accept_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_all_accept_redirects_value='0'
#
# Set runtime for net.ipv4.conf.all.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_redirects="$sysctl_net_ipv4_conf_all_accept_redirects_value"
#
# If net.ipv4.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_redirects = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.accept_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_accept_redirects_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.default.accept_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.accept_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_default_accept_redirects_value='0'
#
# Set runtime for net.ipv4.conf.default.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.accept_redirects="$sysctl_net_ipv4_conf_default_accept_redirects_value"
#
# If net.ipv4.conf.default.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_redirects = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.accept_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_accept_redirects_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv6.conf.all.accept_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv6_conf_all_accept_redirects_value='0'
#
# Set runtime for net.ipv6.conf.all.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_redirects="$sysctl_net_ipv6_conf_all_accept_redirects_value"
#
# If net.ipv6.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_redirects = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_redirects_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.3 - Ensure secure ICMP redirects are not accepted
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.all.secure_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.secure_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.secure_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_all_secure_redirects_value='0'
#
# Set runtime for net.ipv4.conf.all.secure_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.secure_redirects="$sysctl_net_ipv4_conf_all_secure_redirects_value"
#
# If net.ipv4.conf.all.secure_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.secure_redirects = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.secure_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_secure_redirects_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.secure_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.secure_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.default.secure_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.secure_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.secure_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_default_secure_redirects_value='0'
#
# Set runtime for net.ipv4.conf.default.secure_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.secure_redirects="$sysctl_net_ipv4_conf_default_secure_redirects_value"
#
# If net.ipv4.conf.default.secure_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.secure_redirects = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.secure_redirects")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_secure_redirects_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.secure_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.secure_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.4 - Ensure suspicious packets are logged
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.all.log_martians from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.log_martians.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.log_martians" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_all_log_martians_value='1'
#
# Set runtime for net.ipv4.conf.all.log_martians
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.log_martians="$sysctl_net_ipv4_conf_all_log_martians_value"
#
# If net.ipv4.conf.all.log_martians present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.log_martians = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.log_martians")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_log_martians_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.log_martians\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.log_martians\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.default.log_martians from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.log_martians.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.log_martians" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_default_log_martians_value='1'
#
# Set runtime for net.ipv4.conf.default.log_martians
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.log_martians="$sysctl_net_ipv4_conf_default_log_martians_value"
#
# If net.ipv4.conf.default.log_martians present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.log_martians = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.log_martians")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_log_martians_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.log_martians\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.log_martians\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.5 - Ensure broadcast ICMP requests are ignored
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.icmp_echo_ignore_broadcasts from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.icmp_echo_ignore_broadcasts.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.icmp_echo_ignore_broadcasts" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value='1'
#
# Set runtime for net.ipv4.icmp_echo_ignore_broadcasts
#
/sbin/sysctl -q -n -w net.ipv4.icmp_echo_ignore_broadcasts="$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value"
#
# If net.ipv4.icmp_echo_ignore_broadcasts present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.icmp_echo_ignore_broadcasts = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.icmp_echo_ignore_broadcasts")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.icmp_echo_ignore_broadcasts\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.icmp_echo_ignore_broadcasts\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.6 - Ensure bogus ICMP responses are ignored
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.icmp_ignore_bogus_error_responses from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.icmp_ignore_bogus_error_responses.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.icmp_ignore_bogus_error_responses" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_icmp_ignore_bogus_error_responses_value='1'
#
# Set runtime for net.ipv4.icmp_ignore_bogus_error_responses
#
/sbin/sysctl -q -n -w net.ipv4.icmp_ignore_bogus_error_responses="$sysctl_net_ipv4_icmp_ignore_bogus_error_responses_value"
#
# If net.ipv4.icmp_ignore_bogus_error_responses present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.icmp_ignore_bogus_error_responses = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.icmp_ignore_bogus_error_responses")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_icmp_ignore_bogus_error_responses_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.icmp_ignore_bogus_error_responses\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.icmp_ignore_bogus_error_responses\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.7 - Ensure Reverse Path Filtering is enabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_default_rp_filter_value='1'
#
# Set runtime for net.ipv4.conf.default.rp_filter
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"
#
# If net.ipv4.conf.default.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.rp_filter = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.rp_filter")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_rp_filter_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.conf.all.rp_filter from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.rp_filter" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_conf_all_rp_filter_value='1'
#
# Set runtime for net.ipv4.conf.all.rp_filter
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.rp_filter="$sysctl_net_ipv4_conf_all_rp_filter_value"
#
# If net.ipv4.conf.all.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.rp_filter = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.rp_filter")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_rp_filter_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.8 - Ensure TCP SYN Cookies is enabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv4.tcp_syncookies from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.tcp_syncookies.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.tcp_syncookies" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv4_tcp_syncookies_value='1'
#
# Set runtime for net.ipv4.tcp_syncookies
#
/sbin/sysctl -q -n -w net.ipv4.tcp_syncookies="$sysctl_net_ipv4_tcp_syncookies_value"
#
# If net.ipv4.tcp_syncookies present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.tcp_syncookies = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.tcp_syncookies")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_tcp_syncookies_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.tcp_syncookies\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.tcp_syncookies\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.3.9 - Ensure IPv6 router advertisements are not accepted
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv6.conf.all.accept_ra from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_ra.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_ra" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv6_conf_all_accept_ra_value='0'
#
# Set runtime for net.ipv6.conf.all.accept_ra
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_ra="$sysctl_net_ipv6_conf_all_accept_ra_value"
#
# If net.ipv6.conf.all.accept_ra present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_ra = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_ra")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_ra_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_ra\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.accept_ra\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
# Comment out any occurrences of net.ipv6.conf.default.accept_ra from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_ra.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default.accept_ra" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
#
# Set sysctl config file which to save the desired value
#
SYSCONFIG_FILE="/etc/sysctl.conf"
sysctl_net_ipv6_conf_default_accept_ra_value='0'
#
# Set runtime for net.ipv6.conf.default.accept_ra
#
/sbin/sysctl -q -n -w net.ipv6.conf.default.accept_ra="$sysctl_net_ipv6_conf_default_accept_ra_value"
#
# If net.ipv6.conf.default.accept_ra present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.default.accept_ra = value" to /etc/sysctl.conf
#
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.default.accept_ra")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_default_accept_ra_value"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.default.accept_ra\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.default.accept_ra\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 3.5.2.2 - Ensure ufw is uninstalled or disabled with nftables
systemctl stop ufw
apt purge -y ufw

#CIS 3.5.2.9 - Ensure nftables service is enabled
systemctl enable nftables

#CIS 4.1.4.11 - Ensure cryptographic mechanisms are used to protect the integrity of audit tools
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if grep -i '^.*/usr/sbin/auditctl.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi
if grep -i '^.*/usr/sbin/auditd.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi
if grep -i '^.*/usr/sbin/ausearch.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/ausearch.*#/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi
if grep -i '^.*/usr/sbin/aureport.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/aureport.*#/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi
if grep -i '^.*/usr/sbin/autrace.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/autrace.*#/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi
if grep -i '^.*/usr/sbin/augenrules.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/augenrules.*#/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi
if grep -i '^.*/usr/sbin/audispd.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/audispd.*#/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 4.2.1.1.1 - Ensure systemd-journal-remote is installed
apt install -y systemd-journal-remote+

#CIS 4.2.1.3 - Ensure journald is configured to compress large log files
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/systemd/journald.conf" ] ; then
    LC_ALL=C sed -i "/^\s*Compress\s*=\s*/d" "/etc/systemd/journald.conf"
else
    touch "/etc/systemd/journald.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/systemd/journald.conf"
cp "/etc/systemd/journald.conf" "/etc/systemd/journald.conf.bak"
# Insert before the line matching the regex '^#\s*Compress'.
line_number="$(LC_ALL=C grep -n "^#\s*Compress" "/etc/systemd/journald.conf.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^#\s*Compress', insert at
    # the end of the file.
    printf '%s\n' "Compress='yes'" >> "/etc/systemd/journald.conf"
else
    head -n "$(( line_number - 1 ))" "/etc/systemd/journald.conf.bak" > "/etc/systemd/journald.conf"
    printf '%s\n' "Compress='yes'" >> "/etc/systemd/journald.conf"
    tail -n "+$(( line_number ))" "/etc/systemd/journald.conf.bak" >> "/etc/systemd/journald.conf"
fi
# Clean up after ourselves.
rm "/etc/systemd/journald.conf.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 4.2.1.4 - Ensure journald is configured to write logfiles to persistent disk
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/systemd/journald.conf" ] ; then
    LC_ALL=C sed -i "/^\s*Storage\s*=\s*/d" "/etc/systemd/journald.conf"
else
    touch "/etc/systemd/journald.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/systemd/journald.conf"
cp "/etc/systemd/journald.conf" "/etc/systemd/journald.conf.bak"
# Insert before the line matching the regex '^#\s*Storage'.
line_number="$(LC_ALL=C grep -n "^#\s*Storage" "/etc/systemd/journald.conf.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^#\s*Storage', insert at
    # the end of the file.
    printf '%s\n' "Storage='persistent'" >> "/etc/systemd/journald.conf"
else
    head -n "$(( line_number - 1 ))" "/etc/systemd/journald.conf.bak" > "/etc/systemd/journald.conf"
    printf '%s\n' "Storage='persistent'" >> "/etc/systemd/journald.conf"
    tail -n "+$(( line_number ))" "/etc/systemd/journald.conf.bak" >> "/etc/systemd/journald.conf"
fi
# Clean up after ourselves.
rm "/etc/systemd/journald.conf.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 4.2.3 - Ensure all logfiles have appropriate permissions and ownership
readarray -t files < <(find /var/log/)
for file in "${files[@]}"; do
    if basename $file | grep -qE '^.*$'; then
        chmod 0640 $file
    fi
done
if grep -qE "^f \/var\/log\/(btmp|wtmp|lastlog)? " /usr/lib/tmpfiles.d/var.conf; then
    sed -i --follow-symlinks "s/\(^f[[:space:]]\+\/var\/log\/btmp[[:space:]]\+\)\(\([[:digit:]]\+\)[^ $]*\)/\10640/" /usr/lib/tmpfiles.d/var.conf
    sed -i --follow-symlinks "s/\(^f[[:space:]]\+\/var\/log\/wtmp[[:space:]]\+\)\(\([[:digit:]]\+\)[^ $]*\)/\10640/" /usr/lib/tmpfiles.d/var.conf
    sed -i --follow-symlinks "s/\(^f[[:space:]]\+\/var\/log\/lastlog[[:space:]]\+\)\(\([[:digit:]]\+\)[^ $]*\)/\10640/" /usr/lib/tmpfiles.d/var.conf
fi

#CIS 5.1.2 - Ensure permissions on /etc/crontab are configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
chmod u-xs,g-xwrs,o-xwrt /etc/crontab
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.1.3 - Ensure permissions on /etc/cron.hourly are configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
find -H /etc/cron.hourly/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.1.4 - Ensure permissions on /etc/cron.daily are configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
find -H /etc/cron.daily/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.1.5 - Ensure permissions on /etc/cron.weekly are configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
find -H /etc/cron.weekly/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.1.6 - Ensure permissions on /etc/cron.monthly are configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
find -H /etc/cron.monthly/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.1.7 - Ensure permissions on /etc/cron.d are configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
find -H /etc/cron.d/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
chmod u-xs,g-xwrs,o-xwrt /etc/ssh/sshd_config
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.4 - Ensure SSH access is limited
echo "AllowGroups sudo" >> /etc/ssh/sshd_config

#CIS 5.2.5 - Ensure SSH LogLevel is appropriate
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then    
    LC_ALL=C sed -i "/^\s*LogLevel\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "LogLevel INFO" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "LogLevel INFO" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.7 - Ensure SSH root login is disabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then    
    LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "PermitRootLogin no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "PermitRootLogin no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.8 - Ensure SSH HostbasedAuthentication is disabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then 
    LC_ALL=C sed -i "/^\s*HostbasedAuthentication\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "HostbasedAuthentication no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "HostbasedAuthentication no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.9 - Ensure SSH PermitEmptyPasswords is disabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*PermitEmptyPasswords\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "PermitEmptyPasswords no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "PermitEmptyPasswords no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.10 - Ensure SSH PermitUserEnvironment is disabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "PermitUserEnvironment no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "PermitUserEnvironment no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.11 - Ensure SSH IgnoreRhosts is enabled
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*IgnoreRhosts\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "IgnoreRhosts yes" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "IgnoreRhosts yes" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

CIS 5.2.13 - Ensure only strong Ciphers are used
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*Ciphers\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

CIS 5.2.14 - Ensure only strong MAC algorithms are used
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*MACs\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
 make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

CIS 5.2.15 - Ensure only strong Key Exchange algorithms are used
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
sshd_strong_kex='ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256'
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*KexAlgorithms\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "KexAlgorithms $sshd_strong_kex" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "KexAlgorithms $sshd_strong_kex" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.17 - Ensure SSH warning banner is configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*Banner\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "Banner /etc/issue.net" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "Banner /etc/issue.net" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.18 - Ensure SSH MaxAuthTries is set to 4 or less
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
sshd_max_auth_tries_value='4'
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*MaxAuthTries\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "MaxAuthTries $sshd_max_auth_tries_value" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "MaxAuthTries $sshd_max_auth_tries_value" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.19 - Ensure SSH MaxStartups is configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
var_sshd_set_maxstartups='10:30:60'
if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*MaxStartups\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "MaxStartups $var_sshd_set_maxstartups" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "MaxStartups $var_sshd_set_maxstartups" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.20 - Ensure SSH MaxSessions is set to 10 or less
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
var_sshd_max_sessions='10'
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*MaxSessions\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "MaxSessions $var_sshd_max_sessions" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "MaxSessions $var_sshd_max_sessions" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.21 - Ensure SSH LoginGraceTime is set to one minute or less
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
var_sshd_set_login_grace_time='60'
if [ -e "/etc/ssh/sshd_config" ] ; then 
    LC_ALL=C sed -i "/^\s*LoginGraceTime\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "LoginGraceTime $var_sshd_set_login_grace_time" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "LoginGraceTime $var_sshd_set_login_grace_time" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.2.22 - Ensure SSH Idle Timeout Interval is configured
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
sshd_idle_timeout_value='300'
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*ClientAliveInterval\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "ClientAliveInterval $sshd_idle_timeout_value" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "ClientAliveInterval $sshd_idle_timeout_value" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
var_sshd_set_keepalive='3'
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*ClientAliveCountMax\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "ClientAliveCountMax $var_sshd_set_keepalive" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "ClientAliveCountMax $var_sshd_set_keepalive" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.3.3 - Ensure sudo log file exists
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'sudo' 2>/dev/null | grep -q installed; then
var_sudo_logfile='/var/log/sudo.log'
if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults[\s]*\blogfile=("(?:\\"|\\\\|[^"\\\n])*"\B|[^"](?:(?:\\,|\\"|\\ |\\\\|[^", \\\n])*)\b)\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option logfile
        echo "Defaults logfile=${var_sudo_logfile}" >> /etc/sudoers
    else
        # sudoers file defines Option logfile, remediate if appropriate value is not set
        if ! grep -P "^[\s]*Defaults.*\blogfile=${var_sudo_logfile}\b.*$" /etc/sudoers; then
            
            escaped_variable=${var_sudo_logfile//$'/'/$'\/'}
            sed -Ei "s/(^[\s]*Defaults.*\blogfile=)[-]?.+(\b.*$)/\1$escaped_variable\2/" /etc/sudoers
        fi
    fi
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.3.6 - Ensure sudo authentication timeout is configured correctly
if dpkg-query --show --showformat='${db:Status-Status}\n' 'sudo' 2>/dev/null | grep -q installed; then
var_sudo_timestamp_timeout='15'
if grep -Px '^[\s]*Defaults.*timestamp_timeout[\s]*=.*' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -Ei "/^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=.*/d" {} \;
fi
if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*[-]?\w+.*$' /etc/sudoers; then
        # sudoers file doesn't define Option timestamp_timeout
        echo "Defaults timestamp_timeout=${var_sudo_timestamp_timeout}" >> /etc/sudoers
    else
        # sudoers file defines Option timestamp_timeout, remediate if appropriate value is not set
        if ! grep -P "^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*${var_sudo_timestamp_timeout}.*$" /etc/sudoers; then
            sed -Ei "s/(^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=)[[:blank:]]*[-]?\w+(.*$)/\1${var_sudo_timestamp_timeout}\2/" /etc/sudoers
        fi
    fi
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.3.7 - Ensure access to the su command is restricted
var_pam_wheel_group_for_su='sugroup'
if ! grep -q "^${var_pam_wheel_group_for_su}:[^:]*:[^:]*:[^:]*" /etc/group; then
    groupadd ${var_pam_wheel_group_for_su}
fi
# group must be empty
grp_memb=$(groupmems -g ${var_pam_wheel_group_for_su} -l)
if [ -n "${grp_memb}" ]; then
    for memb in ${grp_memb}; do
        deluser ${memb} ${var_pam_wheel_group_for_su}
    done
fi
PAM_CONF=/etc/pam.d/su
pamstr=$(grep -P '^auth\s+required\s+pam_wheel\.so\s+(?=[^#]*\buse_uid\b)(?=[^#]*\bgroup=)' ${PAM_CONF})
if [ -z "$pamstr" ]; then
    sed -Ei '/^auth\b.*\brequired\b.*\bpam_wheel\.so/d' ${PAM_CONF} # remove any remaining uncommented pam_wheel.so line
    sed -Ei "/^auth\s+sufficient\s+pam_rootok\.so.*$/a auth required pam_wheel.so use_uid group=${var_pam_wheel_group_for_su}" ${PAM_CONF}
else
    group_val=$(echo -n "$pamstr" | egrep -o '\bgroup=[_a-z][-0-9_a-z]*' | cut -d '=' -f 2)
    if [ -z "${group_val}" ] || [ ${group_val} != ${var_pam_wheel_group_for_su} ]; then
        sed -Ei "s/(^auth\s+required\s+pam_wheel.so\s+[^#]*group=)[_a-z][-0-9_a-z]*/\1${var_pam_wheel_group_for_su}/" ${PAM_CONF}
    fi
fi

#CIS 5.4.1 - Ensure password creation requirements are configured
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_dcredit='-1'
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^dcredit")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_dcredit"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^dcredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^dcredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_lcredit='-1'
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^lcredit")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_lcredit"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^lcredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^lcredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_minclass='4'
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minclass")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minclass"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minclass\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minclass\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_minlen='14'
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minlen")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minlen"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minlen\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minlen\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_ocredit='-1'
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ocredit")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ocredit"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ocredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ocredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_retry='3'
if [ -e "/etc/pam.d/common-password" ] ; then
    valueRegex="$var_password_pam_retry" defaultValue="$var_password_pam_retry"
    # non-empty values need to be preceded by an equals sign
    [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
    # add an equals sign to non-empty values
    [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"
    # fix 'type' if it's wrong
    if grep -q -P "^\\s*(?"'!'"password\\s)[[:alnum:]]+\\s+[[:alnum:]]+\\s+pam_pwquality.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*)[[:alnum:]]+(\\s+[[:alnum:]]+\\s+pam_pwquality.so)/\\1password\\2/" "/etc/pam.d/common-password"
    fi
    # fix 'control' if it's wrong
    if grep -q -P "^\\s*password\\s+(?"'!'"requisite)[[:alnum:]]+\\s+pam_pwquality.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+)[[:alnum:]]+(\\s+pam_pwquality.so)/\\1requisite\\2/" "/etc/pam.d/common-password"
    fi
    # fix the value for 'option' if one exists but does not match 'valueRegex'
    if grep -q -P "^\\s*password\\s+requisite\\s+pam_pwquality.so(\\s.+)?\\s+retry(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+requisite\\s+pam_pwquality.so(\\s.+)?\\s)retry=[^[:space:]]*/\\1retry${defaultValue}/" "/etc/pam.d/common-password"
    # add 'option=default' if option is not set
    elif grep -q -E "^\\s*password\\s+requisite\\s+pam_pwquality.so" < "/etc/pam.d/common-password" &&
            grep    -E "^\\s*password\\s+requisite\\s+pam_pwquality.so" < "/etc/pam.d/common-password" | grep -q -E -v "\\sretry(=|\\s|\$)" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+requisite\\s+pam_pwquality.so[^\\n]*)/\\1 retry${defaultValue}/" "/etc/pam.d/common-password"
    # add a new entry if none exists
    elif ! grep -q -P "^\\s*password\\s+requisite\\s+pam_pwquality.so(\\s.+)?\\s+retry${valueRegex}(\\s|\$)" < "/etc/pam.d/common-password" ; then
        echo "password requisite pam_pwquality.so retry${defaultValue}" >> "/etc/pam.d/common-password"
    fi
else
    echo "/etc/pam.d/common-password doesn't exist" >&2
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_ucredit='-1'
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ucredit")
# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ucredit"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ucredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ucredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.4.2 - Ensure lockout for failed password attempts is configured
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_accounts_passwords_pam_faillock_deny='4'
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock
authselect apply-changes -b
else 
pam_file="/etc/pam.d/common-auth"
if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$' "$pam_file" ; then
    sed -i --follow-symlinks '/^auth.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth' "$pam_file"
fi
if ! grep -qE '^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail.*$' "$pam_file" ; then
    sed -i --follow-symlinks '/^auth.*pam_unix\.so.*/a auth        [default=die]      pam_faillock.so authfail' "$pam_file"
fi
if ! grep -qE '^\s*auth\s+sufficient\s+pam_faillock\.so\s+authsucc.*$' "$pam_file" ; then
    sed -i --follow-symlinks '/^auth.*pam_faillock\.so.*authfail.*/a auth        sufficient      pam_faillock.so authsucc' "$pam_file"
fi
pam_file="/etc/pam.d/common-account"
if ! grep -qE '^\s*account\s+required\s+pam_faillock\.so.*$' "$pam_file" ; then
    echo 'account   required     pam_faillock.so' >> "$pam_file"
fi
fi
AUTH_FILES=("/etc/pam.d/common-auth" "/etc/pam.d/password-auth")
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*deny\s*="
    line="deny = $var_accounts_passwords_pam_faillock_deny"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(deny\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_deny"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi
                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
                authselect apply-changes -b
            fi
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bdeny\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bdeny\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*deny' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
        fi
    done
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_accounts_passwords_pam_faillock_fail_interval='900'
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock
authselect apply-changes -b
else
pam_file="/etc/pam.d/common-auth"
if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$' "$pam_file" ; then
    sed -i --follow-symlinks '/^auth.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth' "$pam_file"
fi
if ! grep -qE '^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail.*$' "$pam_file" ; then
    sed -i --follow-symlinks '/^auth.*pam_unix\.so.*/a auth        [default=die]      pam_faillock.so authfail' "$pam_file"
fi
if ! grep -qE '^\s*auth\s+sufficient\s+pam_faillock\.so\s+authsucc.*$' "$pam_file" ; then
    sed -i --follow-symlinks '/^auth.*pam_faillock\.so.*authfail.*/a auth        sufficient      pam_faillock.so authsucc' "$pam_file"
fi
pam_file="/etc/pam.d/common-account"
if ! grep -qE '^\s*account\s+required\s+pam_faillock\.so.*$' "$pam_file" ; then
    echo 'account   required     pam_faillock.so' >> "$pam_file"
fi
fi
AUTH_FILES=("/etc/pam.d/common-auth" "/etc/pam.d/password-auth")
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*fail_interval\s*="
    line="fail_interval = $var_accounts_passwords_pam_faillock_fail_interval"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(fail_interval\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_fail_interval"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi
                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"
                authselect apply-changes -b
            fi
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bfail_interval\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bfail_interval\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then 
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*fail_interval' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
        fi
    done
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.4.3 - Ensure password reuse is limited
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then
var_password_pam_unix_remember='5'
if [ -e "/etc/pam.d/common-password" ] ; then
    valueRegex="$var_password_pam_unix_remember" defaultValue="$var_password_pam_unix_remember"
    # non-empty values need to be preceded by an equals sign
    [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
    # add an equals sign to non-empty values
    [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"
    # fix 'type' if it's wrong
    if grep -q -P "^\\s*(?"'!'"password\\s)[[:alnum:]]+\\s+[[:alnum:]]+\\s+pam_unix.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*)[[:alnum:]]+(\\s+[[:alnum:]]+\\s+pam_unix.so)/\\1password\\2/" "/etc/pam.d/common-password"
    fi
    # fix 'control' if it's wrong
    if grep -q -P "^\\s*password\\s+(?"'!'"\[success=[[:alnum:]].*\])[[:alnum:]]+\\s+pam_unix.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+)[[:alnum:]]+(\\s+pam_unix.so)/\\1\[success=[[:alnum:]].*\]\\2/" "/etc/pam.d/common-password"
    fi
    # fix the value for 'option' if one exists but does not match 'valueRegex'
    if grep -q -P "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so(\\s.+)?\\s+remember(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so(\\s.+)?\\s)remember=[^[:space:]]*/\\1remember${defaultValue}/" "/etc/pam.d/common-password"
    # add 'option=default' if option is not set
    elif grep -q -E "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so" < "/etc/pam.d/common-password" &&
            grep    -E "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so" < "/etc/pam.d/common-password" | grep -q -E -v "\\sremember(=|\\s|\$)" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so[^\\n]*)/\\1 remember${defaultValue}/" "/etc/pam.d/common-password"
    # add a new entry if none exists
    elif ! grep -q -P "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so(\\s.+)?\\s+remember${valueRegex}(\\s|\$)" < "/etc/pam.d/common-password" ; then
        echo "password \[success=[[:alnum:]].*\] pam_unix.so remember${defaultValue}" >> "/etc/pam.d/common-password"
    fi
else
    echo "/etc/pam.d/common-password doesn't exist" >&2
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.4.4 - Ensure password hashing algorithm is up to date with the latest standards
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then
var_password_hashing_algorithm='yescrypt'
if grep --silent ^ENCRYPT_METHOD /etc/login.defs ; then
	sed -i "s/^ENCRYPT_METHOD .*/ENCRYPT_METHOD $var_password_hashing_algorithm/g" /etc/login.defs
else
	echo "" >> /etc/login.defs
	echo "ENCRYPT_METHOD $var_password_hashing_algorithm" >> /etc/login.defs
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.5.1.1 - Ensure minimum days between password changes is configured
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then
var_accounts_minimum_age_login_defs='1'
grep -q ^PASS_MIN_DAYS /etc/login.defs && \
  sed -i "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS     $var_accounts_minimum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MIN_DAYS      $var_accounts_minimum_age_login_defs" >> /etc/login.defs
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.5.1.2 - Ensure password expiration is 365 days or less
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then
var_accounts_maximum_age_login_defs='365'
grep -q ^PASS_MAX_DAYS /etc/login.defs && \
  sed -i "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS     $var_accounts_maximum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MAX_DAYS      $var_accounts_maximum_age_login_defs" >> /etc/login.defs
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.5.1.4 - Ensure inactive password lock is 30 days or less
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then
var_account_disable_post_pw_expiration='30'
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^INACTIVE")
# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_account_disable_post_pw_expiration"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^INACTIVE\\>" "/etc/default/useradd"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^INACTIVE\\>.*/$escaped_formatted_output/gi" "/etc/default/useradd"
else
    if [[ -s "/etc/default/useradd" ]] && [[ -n "$(tail -c 1 -- "/etc/default/useradd" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/default/useradd"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/default/useradd"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#CIS 5.5.4 - Ensure default user umask is 027 or more restrictive
var_accounts_user_umask='027'
grep -q "^\s*umask" /etc/bash.bashrc && \
  sed -i -E -e "s/^(\s*umask).*/\1 $var_accounts_user_umask/g" /etc/bash.bashrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> /etc/bash.bashrc
fi
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then
# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^UMASK")
# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_user_umask"
# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^UMASK\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^UMASK\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
readarray -t profile_files < <(find /etc/profile.d/ -type f -name '*.sh' -or -name 'sh.local')
for file in "${profile_files[@]}" /etc/profile; do
  grep -qE '^[^#]*umask' "$file" && sed -i "s/umask.*/umask $var_accounts_user_umask/g" "$file"
done
if ! grep -qrE '^[^#]*umask' /etc/profile*; then
  echo "umask $var_accounts_user_umask" >> /etc/profile
fi

#CIS 5.5.5 - Ensure default user shell timeout is 900 seconds or less
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
var_accounts_tmout='900'
# if 0, no occurence of tmout found, if 1, occurence found
tmout_found=0
for f in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
    if grep --silent '^\s*TMOUT' $f; then
        sed -i -E "s/^(\s*)TMOUT\s*=\s*(\w|\$)*(.*)$/\1TMOUT=$var_accounts_tmout\3/g" $f
        tmout_found=1
        if ! grep --silent '^\s*readonly TMOUT' $f ; then
            echo "readonly TMOUT" >> $f
        fi
        if ! grep --silent '^\s*export TMOUT' $f ; then
            echo "export TMOUT" >> $f
        fi
    fi
done
if [ $tmout_found -eq 0 ]; then
        echo -e "\n# Set TMOUT to $var_accounts_tmout per security requirements" >> /etc/profile.d/tmout.sh
        echo "TMOUT=$var_accounts_tmout" >> /etc/profile.d/tmout.sh
        echo "readonly TMOUT" >> /etc/profile.d/tmout.sh
        echo "export TMOUT" >> /etc/profile.d/tmout.sh
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
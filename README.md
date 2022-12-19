# Pam Saslauthd

This allows authenticating again sasl authd. This is *only* for authentication, authorisation
is NOT checked!

This module is not intended to be use for day-to-day auth to a system. It's designed to be
a backend for [389-ds](https://github.com/389ds/389-ds-base/) and it's pam-pass-through system.

## Configuration with 389-DS

    dsconf localhost plugin pam-pass-through-auth config saslauthd add --include-suffix dc=dev \
        --id-attr sasl_uid --service saslauthd --fallback false --id_map_method ENTRY
    dsconf localhost plugin pam-pass-through-auth enable
    systemctl restart dirsrv@localhost

See saslauthd.pam for an example of the pam.d file you need.

## Testing

The easiest way to test is to link `libpam_saslauthd.so` into your /usr/lib64/security/ folder.
It's best to do this on a throw away system (a container is a good choice!).

    sudo ln -s  /path/to/pam_saslauthd/target/debug/libpam_saslauthd.so /usr/lib64/security/pam_saslauthd.so

You can then test with [pam tester](https://github.com/kanidm/pam_tester) with a custom
`/etc/pam.d/saslauthd` service file.

To run saslauthd against an ldap server you need to configure `/etc/saslauthd.conf` and run `saslauthd -a ldap -d`

An example `/etc/saslauthd.conf` is:

    ldap_auth_method: bind
    ldap_deref: never
    ldap_filter: (user_at_realm=%U@%r)
    ldap_default_realm: # Set your default realm here.
    ldap_referrals: no
    ldap_search_base:
    ldap_servers: ldaps://
    ldap_start_tls: no
    ldap_tls_check_peer: yes


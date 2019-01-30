import os
import testinfra.utils.ansible_runner
import ruamel.yaml as yaml

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


# Get the CVEs declared in the vars
def vulnerable_packages(os, version):
    '''
    Get the list of vulnerabilities as declared in the os-specific
    variable file
    '''
    with open("../../vars/%s%s.yml" % (os.lower(), version)) as stream:
        try:
            vars = (yaml.safe_load(stream))['security_updates']
            return vars
        except yaml.YAMLError as exc:
            print(exc)


def test_security_some_other_way(host):
    '''
    Check that known vulnerable package versions are not installed
    '''
    cves = vulnerable_packages(host.system_info.distribution,
                               host.system_info.release)
    for cve in cves:
        patched_version = cve['patched_version']
        name = cve['name']
        if (host.package(name).is_installed):
            assert (str(host.package(name).version + '-' +
                        host.package(name).release) >=
                    patched_version)

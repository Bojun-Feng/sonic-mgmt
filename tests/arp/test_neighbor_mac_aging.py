import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture
def shutdown_interface(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Fixture to shutdown an interface and guarantee it is brought back up on cleanup."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    intf_to_restore = None

    def do_shutdown(intf):
        nonlocal intf_to_restore
        intf_to_restore = intf
        duthost.shutdown_interface(intf)

    yield do_shutdown

    if intf_to_restore is not None:
        duthost.no_shutdown_interface(intf_to_restore)


class TestNeighborMacAging:
    @pytest.fixture(params=[4, 6])
    def ipVersion(self, request):
        """
            Parameterized fixture for IP versions. This Fixture will run the test twice for both
            IPv4 and IPv6

            Args:
                request: pytest request object

            Returns:
                ipVersion (int): IP version to be used for testing
        """
        yield request.param

    def _find_neighbor(self, asichost, ipVersion):
        """
            Find a neighbor IP and its interface for the given IP version.

            Args:
                asichost (SonicAsic): ASIC instance on the DUT
                ipVersion (int): IP version (4 or 6)

            Returns:
                dut_intf (str): Interface name, or None if not found
                neighbor_ip (str): Neighbor IP address, or None if not found
        """
        if ipVersion == 4:
            ip_interfaces = asichost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
            logger.debug("ip_interfaces: " + str(ip_interfaces))
            for intf in ip_interfaces.keys():
                if "peer_ipv4" in ip_interfaces[intf] and ip_interfaces[intf]["peer_ipv4"] != "N/A":
                    return intf, ip_interfaces[intf]["peer_ipv4"]
        else:
            ipv6_interfaces = asichost.show_ipv6_interface()["ansible_facts"]["ipv6_interfaces"]
            logger.debug("ipv6_interfaces: " + str(ipv6_interfaces))
            for intf in ipv6_interfaces.keys():
                if "peer_ipv6" in ipv6_interfaces[intf] and ipv6_interfaces[intf]["peer_ipv6"] != "N/A":
                    return intf, ipv6_interfaces[intf]["peer_ipv6"]

        return None, None

    def testNeighborMacAgingAfterIntfDown(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                          enum_rand_one_frontend_asic_index, shutdown_interface, ipVersion):
        """
            Test whether neighbor MAC is aged out after interface down

            Args:
                duthosts: DUT hosts fixture
                enum_rand_one_per_hwsku_frontend_hostname: random frontend DUT
                enum_rand_one_frontend_asic_index: random frontend ASIC
                shutdown_interface: fixture to shutdown/restore interface
                ipVersion (Fixture<int>): IP version to be tested

            Returns:
                None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

        dut_intf, neighbor_ip = self._find_neighbor(asichost, ipVersion)
        if dut_intf is None:
            pytest.skip("No IPv{} neighbor found on DUT".format(ipVersion))

        logger.debug("DUT interface: {}, neighbor IP: {}".format(dut_intf, neighbor_ip))

        # Verify that the MAC address is present in the ARP table and ASIC_DB
        arp_entry = duthost.command("{} neigh show {}".format(asichost.ip_cmd, neighbor_ip))['stdout_lines'][0]
        redis_entry = duthost.command("{} ASIC_DB KEYS \"ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*\\\"{}\\\"*\""
                                      .format(asichost.sonic_db_cli, neighbor_ip))['stdout_lines'][0]
        pytest_assert(arp_entry, "ARP entry not found")
        pytest_assert(redis_entry, "Redis entry not found")

        # Shutdown the interface on DUT
        shutdown_interface(dut_intf)

        def check_neighbor_aged_out():
            arp_lines = duthost.command("{} neigh show {}".format(
                asichost.ip_cmd, neighbor_ip))['stdout_lines']
            redis_lines = duthost.command("{} ASIC_DB KEYS \"ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*{}*\"".format(
                asichost.sonic_db_cli, neighbor_ip))['stdout_lines']
            return len(arp_lines) == 0 and len(redis_lines) == 0

        # Verify that the MAC address is aged out from the ARP table and ASIC_DB
        pytest_assert(wait_until(120, 10, 0, check_neighbor_aged_out),
                      "ARP/Redis entry not aged out after interface down")

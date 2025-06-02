#!/user/bin/env python
# -*- coding:utf-8 -*-


import os
import sys
import time
import json
import requests
import ipaddress
import socket
import platform
import subprocess
import logging
from logging.handlers import RotatingFileHandler

# translate English result to Chinese
EnglishChineseDict = {
    "Traffic_Direction": "数据方向",
    "Send_Packets": "发送包数",
    "Receive_Packets": "接收包数",
    "CrcError_Packets": "CRC错误包数",
    "Send_Mbps": "发送速率(Mbps)",
    "Send_Mbps_Percentage": "发送线速百分比",
    "Receive_Mbps": "接收速率(Mbps)",
    "Receive_Mbps_Percentage": "接收线速百分比",
    "Frame_Persend_Second": "发送帧率(FPS)",
    "Frame_Perrecv_Second": "接收帧率(FPS)",
    "Lose_Rate": "丢包率",
    "Lose_Rate_Passed": "结果",
    "Direction": "流量方向",
    "TrafficFlow": "数据方向",
    "CycleID": "循环ID",
    "FrameBytes": "帧长(字节)"
}

# the same as web menu
CaseClassifyDict = {
    "L4-7ProtocolTest": ["HttpCps", "HttpForceCps", "HttpCc", "HttpThroughput", "HttpsCps", "HttpsCc", "HttpsThroughput",
                         "SSLHandshake", "Http2Cps", "Http2Throughput", "Http3Cps", "Http3Throughput", "WebSocketRps",
                         "BrowserTrafficTest", "RtspPps", "RtspPq", "RtspPc", "RtpVideo", "RtpAudio", "Hls", "Rtmp",
                         "GB28181", "MailSmtp", "MailSmtps", "MailPop3", "MailImap", "ModbusCps", "ModbusThroughput",
                         "ModbusCc", "OPCUACps", "OPCUAThroughput", "OPCUACc", "S7COMMCps", "S7COMMThroughput", "S7COMMCc",
                         "IEC61850_MMSCps", "IEC61850_MMSThroughput", "IEC61850_MMSCc", "S7", "Dnp3", "IEC61850", "UdpPps",
                         "TurboTcp", "TcpThroughput", "PostgreSql", "MySQL", "MqttCps", "Ftp", "Ldap", "Ssh", "Rdp", "Telnet",
                         "UdpPayload", "Ntp", "Handle", "Tftp", "Radius", "DHCPv4", "DHCPv6", "TcpDns", "UdpDns", "DnsOverHttps",
                         "DnsOverTls", "Sip", "SslVpnCc", "PrivStreamCps", "PrivStream", "PrivStreamCc", "MixedTraffic"],
    "L2-3ProtocolTest": ["Rip", "RIPng", "Ospfv2", "Ospfv3", "BGPv4", "BGPv6", "ISISv4", "ISISv6", "Igmp", "Mld", "Pim",
                         "PimSm", "PimSsm", "PcapResend", "PPPoEHttpAuth", "MplsLdpSession", "MPLSIPVPN", "L3EVPNOverSRv6",
                         "VPWSOverSRv6", "VPLSOverSRv6", "VXLAN", "Netconf", "L2TP", "LACP", "LLDP", "Rfc2544Throughput",
                         "Rfc2544Latency", "Rfc2544LossRate", "Rfc2544BackToBack", "Rfc2889AddressLearnRate", "Rfc2889AddressCacheCapacity",
                         "Rfc2889ForwardingRates", "Rfc3918Throughput", "Rfc3918GroupForwardMatrix", "IPSecRemoteAccess",
                         "IPSecTunnelCc", "IPSecThroughput", "StreamTemplate", "FastTrafficReplay"],
    "PrivateNetTest": ["RoCEv2Perftest", "RoCEv2Cps", "RoCEv2Throughput", "RoCEv2CCL", "RoCEv2ExceptionTest", "RoCEv2NakFloodingAttack",
                       "RoCEv2CpsAttack", "SignalingSimulationTestNode", "SignalingSimulationTestProcess", "SignalingSimulationTestDataStatistics",
                       "ElementSimulationTestManagement", "ElementSimulationScriptManagement", "BaseStationConnThroughput",
                       "PC5VehicleToVehicleInteraction", "UuVehicleCloudInteraction"],
    "NetSecurityTest": ["VulnerabilityScanner", "WebScanner", "NetworkDiscovery", "WeakPasswordDetection", "Ipv4FragAttack",
                        "ICMPSinglePacketAttack", "IGMPv4SinglePacketAttack", "ARPv4SinglePacketAttack", "TCPSinglePacketAttack",
                        "UDPSinglePacketAttack", "UDPPayloadAttack", "SipSinglePacketAttack", "DnsServiceAttack", "DnsAmplificationAttack",
                        "SSDPAttack", "NtpAmplificationAttack", "MemcachedAmplificationAttack", "UnknownProtocolSinglePacketAttack",
                        "HttpRequestFlood", "HttpsFlood", "HTTPSlowRequestFlood", "MultiTypeFlood", "TcpSessionFlood",
                        "TCPWinnuke", "HttpMultipleRequest", "HttpRecursionRequest", "HttpConcurrentSlowRead", "HttpConcurrentSlowRequest",
                        "UnicastStorm", "BroadcastStorm", "MulticastStorm", "SVStormTest", "GooseStormTest", "MmsConnectStorm",
                        "LLDPStormTest", "AttackReplay", "EncryptionAndDecryptionVerification", "GMT0018", "FirewallPolicy",
                        "MaliciousCodeCheck", "AdvancedFuzzing", "WebSiteScan", "ScenarioDescrptionLanguage", "DynamicProtectionTest"],
    "TestAnalysisTool": ["XinChuang", "Sysbench", "FloatingPointComputingPower", "StreamMemoryTest", "Fio", "VdbenchDiskPerfTest",
                         "Jmeter", "IPerfThroughput", "AbNginxCps", "UPerfCc", "CaptureForward", "PcapParser", "ConcurrentScanCheck",
                         "ProbeCall"]
}


class LoggerUtils:
    _logger = None

    @staticmethod
    def get_logger(name='project') -> logging.Logger:
        if LoggerUtils._logger:
            return LoggerUtils._logger

        log_file = os.path.join(os.getcwd(), 'project.log')  # current directory

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        # console log
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch_formatter = logging.Formatter('[%(levelname)s] %(message)s')
        ch.setFormatter(ch_formatter)

        # log file, max size 5MB, Keep five old files
        fh = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=5,
            encoding='utf-8'
        )
        fh.setLevel(logging.DEBUG)
        fh_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        fh.setFormatter(fh_formatter)

        logger.addHandler(ch)
        logger.addHandler(fh)

        LoggerUtils._logger = logger
        return logger


logger = LoggerUtils.get_logger()

"""
  Tool class encapsulation
"""


class ToolsUtils:
    @staticmethod
    def check_test_case_name(test_case_name):
        """
        * Verify whether the name of the use case is legal
        :param test_case_name:
        :return:
        """
        import re
        if re.match(r'^[\u4e00-\u9fa5a-zA-Z0-9:_-]+$', test_case_name):
            return True
        else:
            return False

    @staticmethod
    def is_ddos_type(test_type):
        """
        * check if the test type is ddos type
        """
        ddos_attack_list = [
            'Ipv4FragAttack',
            'ICMPv4SinglePacketAttack',
            'ICMPv6SinglePacketAttack',
            'ICMPSinglePacketAttack',
            'IGMPv4SinglePacketAttack',
            'ARPv4SinglePacketAttack',
            'TCPv4SinglePacketAttack',
            'TCPv6SinglePacketAttack',
            'TCPSinglePacketAttack',
            'UDPv4SinglePacketAttack',
            'UDPv6SinglePacketAttack',
            'UDPSinglePacketAttack',
            "UDPPayloadAttack",
            "SipSinglePacketAttack",
            'DnsServiceAttack',
            'DnsAmplificationAttack',
            'SSDPAttack',
            'NtpAmplificationAttack',
            'MemcachedAmplificationAttack',
            'UnknownProtocolSinglePacketAttack',
            # DDos session attack
            'MultiTypeFlood',
            'TcpSessionFlood',
            'TCPWinnuke',
            'HttpRequestFlood',
            'HttpMultipleRequest',
            'HttpRecursionRequest',
            'HTTPSlowRequestFlood',
            'HttpConcurrentSlowRead',
            'HttpConcurrentSlowRequest',
            'HttpsFlood',
            # network storm attack
            'UnicastStorm',
            'BroadcastStorm',
            'MulticastStorm',
            'SVStormTest',
            'GooseStormTest',
            'MmsConnectStorm',
            'LLDPStormTest'
        ]

        if test_type in ddos_attack_list:
            return True
        else:
            return False

    @staticmethod
    def is_non_dpdk_test_type(test_type):
        non_dpdk_list = [
            "Jmeter",
            "AbNginxCps",
            "AbNginxCc",
            "IPerfThroughput",
            "AdvancedFuzzing",
            "ScenarioDescrptionLanguage",
            "VulnerabilityScanner",
            "WebScanner",
            "NetworkDiscovery",
            "FirewallPolicy",
            "IPv6ConformanceTest",
            "IPSecRemoteAccess",
            "IPSecTunnelCc",
            "IPSecThroughput",
            "SslVpnCc",
            "GMT0018",
            "Netconf",
            "AutoTestAccessPolicy",
            "UPerfCc",
            "SystemMonitor",
            "DynamicProtectionTest",
            "WebSiteScan",
            "ProbeCall",
            "Sysbench",
            "VdbenchDiskPerfTest",
            "Fio",
            "FloatingPointComputingPower",
            "StreamMemoryTest",
            "WeakPasswordDetection",
        ]

        if test_type in non_dpdk_list:
            return True

        return False

    @staticmethod
    def is_dpdk_test_type(test_type):
        test_type_list = [
            "HttpCps",
            "HttpsCps",
            "HttpCc",
            "HttpsCc",
            "HttpRps",
            "HttpsRps",
            "HttpThroughput",
            "HttpsThroughput",
            "HttpHts",
            "HttpsHts",
            "Http2Cps",
            "Http3Cps",
            "Http3Throughput",
            "SSLHandshake",
            "Http2Throughput",
            "Private",
            "PacketAssembly",
            "StreamTemplate",
            "TcpConnection",
            "TcpThroughput",
            "TurboTcp",
            "UdpPps",
            "UdpPayload",
            "AttackReplay",
            "TrafficReplay",
            "FastTrafficReplay",
            "ICSReplay",
            "MailSmtp",
            "MailSmtps",
            "PostgreSql",
            "MailPop3",
            "MailImap",
            "Ipv46SinglePacketFlood",
            "Ipv4SinglePacketFlood",
            "UDPv4SinglePacketAttack",
            "UDPv6SinglePacketAttack",
            # 合并v4v6
            "UDPSinglePacketAttack",
            "ARPv4SinglePacketAttack",
            "IGMPv4SinglePacketAttack",
            "TCPv4SinglePacketAttack",
            "TCPv6SinglePacketAttack",
            # 合并v4v6
            "TCPSinglePacketAttack",
            "ICMPv4SinglePacketAttack",
            "ICMPv6SinglePacketAttack",
            # 合并v4v6
            "ICMPSinglePacketAttack",
            "UnknownProtocolSinglePacketAttack",
            "DnsAmplificationAttack",
            "NtpAmplificationAttack",
            "DnsServiceAttack",
            "TcpSessionFlood",
            'TCPWinnuke',
            "HttpRequestFlood",
            "HttpMultipleRequest",
            "HttpRecursionRequest",
            "HttpConcurrentSlowRead",
            "HttpConcurrentSlowRequest",
            "HttpsFlood",
            "HttpSessionFlood",
            "ConcurrentSessionFlood",
            "UdpDns",
            "MixedTraffic",
            "Rfc2544BaseValue",
            "Rfc2544Throughput",
            "Rfc2544Latency",
            "Rfc2544LossRate",
            "Rfc2544BackToBack",
            "Rfc2889AddressCacheCapacity",
            "Rfc2889AddressLearnRate",
            "Rfc2889ForwardingRates",
            "Rfc3918Latency",
            "Rfc3918GroupForwardMatrix",
            "Rfc3918v6GroupForwardMatrix",
            "Rfc3511IpThroughput",
            "Rfc3511Cc",
            "Rfc3511Cr",
            "Rfc3511Tsr",
            "Rfc3511Tfr",
            "Rfc3511IpFragmentation",
            "Rfc3511DosHandling",
            "Rfc3511IllegalHandling",
            "Rfc3511Latency",
            "IPSecRemoteAccess",
            "IPSecTunnelCc",
            "IPSecThroughput",
            "IPSecSiteToSite",
            "Ftp",
            "Tftp",
            "Rtsp",
            "RtspPps",
            "RtspPc",
            "RtspPq",
            "RtspPtr",
            "RtpVideo",
            "RtpAudio",
            "Ntp",
            "Radius",
            "Dhcp",
            "DHCPv4",
            "DHCPv6",
            "IPoE",
            "IPoeHttpAuth",
            "PPPoEHttpAuth",
            "L2TP",
            "Igmp",
            "Mld",
            "Ldap",
            "PacketCapture",
            "CaptureForward",
            "FirewallAttack",
            "FirewallMalware",
            "Modbus",
            "Dnp3",
            "ConcurrentScanCheck",
            "MaliciousCodeCheck",
            "MultiTypeFlood",
            "MySQL",
            "MQTT",
            "Choice5GMCI",
            "Sip",
            "Ipv4FragAttack",
            "PrivStream",
            "IEC61850_MMSCc",
            "IEC61850_MMSCps",
            "IEC61850_MMSThroughput",
            "IEC61850",
            "DB_PostgreSQL",
            "DB_Oracle",
            "DB_MySQL",
            "DB_MongoDB",
            "Rip",
            "VXLAN",
            "Ospfv2",
            "Ospfv3",
            "Handle",
            "RIPng",
            "MplsLdpSession",
            "DnsHttp",
            "Ssh",
            "Rdp",
            "DnsOverHttps",
            "Telnet",
            "Rtmp",
            "Samba",
            "Hls",
            "H323",
            "Rfc3918Throughput",
            "ICS_IEC60870_5_104",
            "ICS_IEC61850_GOOSE",
            "ICS_IEC61850_MMS",
            "ICS_OPC_UA_DA",
            "ICS_SIEMENS_S7",
            "BGPv4",
            "BGPv6",
            "ModbusCps",
            "OPCUA",
            "S7COMM",
            "S7COMMCps",
            "S7COMMCc",
            "S7COMMThroughput",
            "MPLSIPVPN",
            "L3EVPNOverSRv6",
            "EVPNVPWSOverSRv6",
            "EVPNVPLSOverSRv6",
            "ModbusThroughput",
            "ModbusCc",
            "OPCUACc",
            "OPCUAThroughput",
            "OPCUACps",
            "ISISv4",
            "ISISv6",
            "LACP",
            "LLDP",
            "Gpro",
            "PrivStreamCps",
            "PrivStreamCc",
            "TrafficStream",
            "UnicastStorm",
            "BroadcastStorm",
            "MulticastStorm",
            "WebSocketRps",
            "UDPPayloadAttack",
            "TcpDns",
            "GB28181",
            "GMT0018",
            "Netconf",
            "5gSip",
            "S7",
            "MemcachedAmplificationAttack",
            "SSDPAttack",
            "MmsConnectStorm",
            "SVStormTest",
            "LLDPStormTest",
            "SystemMonitor",
            "GooseStormTest",
            "HTTPSlowRequestFlood",
            "PcapResend",
            "SipSinglePacketAttack",
            "DnsOverTls",
            "RoCEv2",
            "HttpForceCps",
            "HttpOverlapCps",
            "VPWSOverSRv6",
            "VPLSOverSRv6",
            "Pim",
            "RoCEv2Throughput",
            "PimSm",
            "RoCEv2CCL",
            "PimSsm",
            "PSNOutOfOrderSttack",
            "ICRCErrorAttack",
            "RoCEv2ExceptionTest",
            "RoCEv2NakFloodingAttack",
            "SatelliteHttpsCc",
            "SatelliteHttpCc",
            "SatelliteHttpsCps",
            "SatelliteHttpCps",
            "SatelliteRtspPps",
            "SatelliteRtpVideo",
            "SatelliteRtpAudio",
            "SatelliteUdpPps",
            "SatelliteTcpThroughout",
            "SatelliteHttpThroughout",
            "SatelliteHttpsThroughout",
            "SatelliteTurboTcp",
            "BaseStationConnCps",
            "BaseStationConnCc",
            "BaseStationConnThroughput",
            "TrafficGenerator",
            "RoCEv2CpsAttack",
            "MqttCps"
        ]
        if test_type in test_type_list:
            return True

        return False

    @staticmethod
    def to_dict(instance):
        """
        * Tool class
        :param :
        :return:
        """
        return {
            k: (v[0] if isinstance(v, tuple) else v)
            for k, v in instance.__dict__.items()
            if not k.startswith("_")
        }


"""
  Network tool class encapsulation
"""


class NetworkUtils:
    @staticmethod
    def ping_host(host, count=1, timeout=1):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            result = subprocess.run(
                ['ping', param, str(count), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def check_port(host, port, timeout=1):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False


"""
  Port speed limit class encapsulation
"""


class PortSpeedLimit:
    def __init__(self, test_type):
        self.LimitMode = "Interface"
        self.LimitType = "case"
        self.LimitGraph = "fixed"
        self.SpeedLimit = 0
        self.Accumulate = "slice_add"
        self.FlushTokenUsecond = "1000"
        self.Name = "HttpCps"
        self.TestType = "HttpCps"

        if test_type == "HttpForceCps":
            self.LimitForwardModel = "StrongRate"
            self.StrongLimitValue = 10000

        if test_type in ["BGPv4", "BGPv6"]:
            self.BandwidthUnit = "Mbps"

    def set_limit_mode(self, mode):
        """
        Set the speed limit mode.

        Args:
            mode (str): The speed limit mode to be set.
        """
        self.LimitMode = mode

    def set_limit_type(self, type):
        """
        Set the speed limit type.

        Args:
            type (str): The speed limit type to be set.
        """
        self.LimitType = type

    def set_limit_graph(self, graph):
        """
        Set the speed limit graph.

        Args:
            graph (str): The speed limit graph to be set.
        """
        self.LimitGraph = graph

    def set_speed_limit(self, limit):
        """
        Set the speed limit value.

        Args:
            limit (int): The speed limit value to be set.
        """
        self.SpeedLimit = limit

    def set_accumulate(self, accumulate):
        """
        Set the accumulation method.

        Args:
            accumulate (str): The accumulation method to be set.
        """
        self.Accumulate = accumulate

    def set_flush_token_usecond(self, usecond):
        """
        Set the time in microseconds to flush tokens.

        Args:
            usecond (str): The time in microseconds to flush tokens.
        """
        self.FlushTokenUsecond = usecond

    def set_name(self, name):
        """
        Set the name.

        Args:
            name (str): The name to be set.
        """
        self.Name = name

    def set_test_type(self, test_type):
        """
        Set the test type.

        Args:
            test_type (str): The test type to be set.
        """
        self.TestType = test_type

    def set_limit_forward_model(self, limit_forward_model):
        """
        Set the test type.

        Args:
            limit_forward_model (str): The test type to be set.
        """
        self.LimitForwardModel = limit_forward_model

    def set_strong_limit_value(self, strong_limit_value):
        """
        Set the strong limit value.

        Args:
            strong_limit_value (str): The test type to be set.
        """
        self.StrongLimitValue = strong_limit_value

    def to_dict(self):
        return self.__dict__


"""
  Virtual User Rate Limiting Encapsulation
"""


class SimUserSpeedLimit:
    """
    Represents the configuration class for simulated user speed limit, used to manage various parameters of simulated user speed limit.
    """

    def __init__(self):
        """
        Initialize an instance of the SimUserSpeedLimit class and set the default simulated user speed limit parameters.
        """
        self.LimitMode = "Interface"  # The mode of speed limit, default is "Interface"
        self.LimitType = "simuser"  # The type of speed limit, default is "simuser"
        self.LimitGraph = "fixed"  # The graph of speed limit, default is "fixed"
        self.Accumulate = "slice_add"  # The accumulation method, default is "slice_add"
        self.FlushTokenUsecond = "1000"  # The flush token time in microseconds, default is "1000"
        self.IterationStandard = 95  # The iteration standard, default is 95
        self.IterationRange = 5  # The iteration range, default is 5
        self.StabilizeTestTime = 5  # The stabilization test time, default is 5
        self.Name = "HttpCps"  # The name of the speed limit, default is "HttpCps"
        self.TestType = "HttpCps"  # The test type related to the speed limit, default is "HttpCps"

    def set_limit_mode(self, mode):
        """
        Set the speed limit mode.

        Args:
            mode (str): The speed limit mode to be set.
        """
        self.LimitMode = mode

    def set_limit_type(self, type):
        """
        Set the speed limit type.

        Args:
            type (str): The speed limit type to be set.
        """
        self.LimitType = type

    def set_limit_graph(self, graph):
        """
        Set the speed limit graph.

        Args:
            graph (str): The speed limit graph to be set.
        """
        self.LimitGraph = graph

    def set_accumulate(self, accumulate):
        """
        Set the accumulation method.

        Args:
            accumulate (str): The accumulation method to be set.
        """
        self.Accumulate = accumulate

    def set_flush_token_usecond(self, usecond):
        """
        Set the time in microseconds to flush tokens.

        Args:
            usecond (str): The time in microseconds to flush tokens.
        """
        self.FlushTokenUsecond = usecond

    def set_iteration_standard(self, standard):
        """
        Set the iteration standard.

        Args:
            standard (int): The iteration standard to be set.
        """
        self.IterationStandard = standard

    def set_iteration_range(self, range):
        """
        Set the iteration range.

        Args:
            range (int): The iteration range to be set.
        """
        self.IterationRange = range

    def set_stabilize_test_time(self, time):
        """
        Set the stabilization test time.

        Args:
            time (int): The stabilization test time to be set.
        """
        self.StabilizeTestTime = time

    def set_name(self, name):
        """
        Set the name.

        Args:
            name (str): The name to be set.
        """
        self.Name = name

    def set_test_type(self, test_type):
        """
        Set the test type.

        Args:
            test_type (str): The test type to be set.
        """
        self.TestType = test_type

    def to_dict(self):
        """
        Convert the attributes of the SimUserSpeedLimit instance to a dictionary.

        Returns:
            dict: A dictionary containing the simulated user speed limit configuration information.
        """
        return self.__dict__


class PacketCapture:
    def __init__(self):
        self.CapturePacketEnable = "no"
        self.MgmtIp = "192.168.18.147"
        self.PhysicalPort = "port1"
        self.CaptureProtocol = "None"
        self.CaptureMessage = "All"

    def set_capture_packet_enable(self, enable: str):
        if enable in ["yes", "no"]:
            self.CapturePacketEnable = enable
        else:
            raise ValueError(f"The input param {enable} is an invalid identifier.")

    def set_mgmt_ip(self, ip: str):
        try:
            # Try to convert the string to an IPv4 address object
            ipv4_obj = ipaddress.IPv4Address(ip)
            # print(ipv4_obj)
            self.MgmtIp = ipv4_obj
        except ValueError:
            # If the conversion fails, throw an exception indicating that the string is not a valid IPv4 address
            raise ValueError(f"The input param {ip} is an invalid identifier.")

    def set_physical_port(self, port: str):
        if port in ["port1", "port2", "port3", "port4"]:
            self.PhysicalPort = port
        else:
            raise ValueError(f"The input param '{port}' is an invalid identifier.")

    def set_capture_protocol(self, protocol: str):
        if protocol in ["ALL", "None", "ARP", "DNP", "ICMP", "IGMP", "TCP", "UDP"]:
            self.PhysicalPort = protocol
        else:
            raise ValueError(f"The input param '{protocol}' is an invalid identifier.")

    def set_capture_message(self, message: str):
        if message in ["ALL", "None", "PAUSE", "TCP_SYN", "TCP_RE"]:
            self.CaptureMessage = message
        else:
            raise ValueError(f"The input param '{message}' is an invalid identifier.")

    def set_capture_ip(self, ip_str: str):
        try:
            # Try to convert the string to an IPv4 address
            ip = ipaddress.IPv4Address(ip_str)
            return ip
        except ValueError:
            try:
                # If it's not an IPv4 address, try to convert it to an IPv6 address
                ip = ipaddress.IPv6Address(ip_str)
                return ip
            except ValueError:
                # If it's neither an IPv4 nor an IPv6 address, throw an exception
                raise ValueError(f"The input param '{ip_str}' is an invalid identifier.")

    def set_capture_port(self, port: str):
        if 0 <= int(port) <= 65535:
            self.CapturePort = port
        else:
            raise ValueError(f"The input param '{port}' is an invalid identifier.")

    def set_capture_max_file_size(self, max_file_size: str):
        if 0 <= int(max_file_size) <= 2000:
            self.CaptureMaxFileSize = max_file_size
        else:
            raise ValueError(f"The input param {max_file_size} is an invalid identifier.")

    def set_capture_packat_count(self, packat_count: str):
        if 0 <= int(packat_count) <= 12000000:
            self.CapturePackatCount = packat_count
        else:
            raise ValueError(f"The input param {packat_count} is an invalid identifier.")

    def to_dict(self):
        """
        Convert the attributes of the PacketCapture object to a dictionary.

        Returns:
            dict: A dictionary containing all the attributes of the object.
        """
        return self.__dict__


class PacketFilter:
    def __init__(self):
        # Whether packet filtering is enabled, default is "no"
        self.PacketFilterEnable = "no"
        # Filter action, default is "Drop"
        self.FilterAction = "Drop"
        # Filtering protocol, default is "All"
        self.FilteringProtocol = "All"
        # Filtering IP version, default is "v4"
        self.FilteringIPVersion = "v4"
        # Source port matching rule, default is "Eq"
        self.SrcPortMathes = "Eq"
        # Destination port matching rule, default is "Eq"
        self.DstPortMathes = "Eq"

    def set_capture_packet_enable(self, enable: str):
        """
        Set whether packet capture is enabled.

        Args:
            enable (str): Either "yes" or "no".

        Raises:
            ValueError: If the input is not "yes" or "no".
        """
        if enable in ["yes", "no"]:
            self.CapturePacketEnable = enable
        else:
            raise ValueError(f"The input param '{enable}' is an invalid identifier.")

    def set_filter_action(self, action: str):
        """
        Set the filter action.

        Args:
            action (str): Either "Drop" or "Queue".

        Raises:
            ValueError: If the input is not "Drop" or "Queue".
        """
        if action in ["Drop", "Queue"]:
            self.PhysicalPort = action
        else:
            raise ValueError(f"The input param '{action}' is an invalid identifier.")

    def set_filtering_protocol(self, protocol: str):
        """
        Set the filtering protocol.

        Args:
            protocol (str): Can be "All", "TCP", or "UDP".

        Raises:
            ValueError: If the input is not "All", "TCP", or "UDP".
        """
        if protocol in ["All", "TCP", "UDP"]:
            self.PhysicalPort = protocol
        else:
            raise ValueError(f"The input param '{protocol}' is an invalid identifier.")

    def set_filtering_ip_Version(self, Version: str):
        """
        Set the filtering IP version.

        Args:
            Version (str): Either "v4" or "v6".

        Raises:
            ValueError: If the input is not "v4" or "v6".
        """
        if Version in ["v4", "v6"]:
            self.PhysicalPort = Version
        else:
            raise ValueError(f"The input param '{Version}' is an invalid identifier.")

    def set_src_port_mathes(self, src_port_mathes: str):
        """
        Set the source port matching rule.

        Args:
            src_port_mathes (str): Either "Eq" or "Neq".

        Raises:
            ValueError: If the input is not "Eq" or "Neq".
        """
        if src_port_mathes in ["Eq", "Neq"]:
            self.PhysicalPort = src_port_mathes
        else:
            raise ValueError(f"The input param '{src_port_mathes}' is an invalid identifier.")

    def set_dst_port_mathes(self, dst_port_mathes: str):
        """
        Set the destination port matching rule.

        Args:
            dst_port_mathes (str): Either "Eq" or "Neq".

        Raises:
            ValueError: If the input is not "Eq" or "Neq".
        """
        if dst_port_mathes in ["Eq", "Neq"]:
            self.PhysicalPort = dst_port_mathes
        else:
            raise ValueError(f"The input param '{dst_port_mathes}' is an invalid identifier.")

    def set_filtering_src_ipv4(self, ip: str):
        """
        Set the source IPv4 address for filtering.

        Args:
            ip (str): A valid IPv4 address.

        Raises:
            ValueError: If the input is not a valid IPv4 address.
        """
        try:
            ipv4_obj = ipaddress.IPv4Address(ip)
            self.FilteringSrcIpv4 = ipv4_obj
        except ValueError:
            raise ValueError(f"The input param {ip} is an invalid identifier.")

    def set_filtering_src_ipv6(self, ip: str):
        """
        Set the source IPv6 address for filtering.

        Args:
            ip (str): A valid IPv6 address.

        Raises:
            ValueError: If the input is not a valid IPv6 address.
        """
        try:
            ipv6_obj = ipaddress.IPv6Address(ip)
            self.FilteringSrcIpv6 = ipv6_obj
        except ValueError:
            raise ValueError(f"The input param {ip} is an invalid identifier.")

    def set_filtering_dst_ipv4(self, ip: str):
        """
        Set the destination IPv4 address for filtering.

        Args:
            ip (str): A valid IPv4 address.

        Raises:
            ValueError: If the input is not a valid IPv4 address.
        """
        try:
            ipv4_obj = ipaddress.IPv4Address(ip)
            self.FilteringDstIpv4 = ipv4_obj
        except ValueError:
            raise ValueError(f"The input param {ip} is an invalid identifier.")

    def set_filtering_dst_ipv6(self, ip: str):
        """
        Set the destination IPv6 address for filtering.

        Args:
            ip (str): A valid IPv6 address.

        Raises:
            ValueError: If the input is not a valid IPv6 address.
        """
        try:
            ipv6_obj = ipaddress.IPv6Address(ip)
            self.FilteringDstIpv6 = ipv6_obj
        except ValueError:
            raise ValueError(f"The input param {ip} is an invalid identifier.")

    def set_filtering_src_port(self, src_port: str):
        """
        Set the source port for filtering.

        Args:
            src_port (str): A valid port number between 0 and 65535.

        Raises:
            ValueError: If the input is not a valid port number.
        """
        if 0 <= int(src_port) <= 65535:
            self.FilteringSrcPort = src_port
        else:
            raise ValueError(f"The input param '{src_port}' is an invalid identifier.")

    def set_filtering_dst_port(self, dst_port: str):
        """
        Set the destination port for filtering.

        Args:
            dst_port (str): A valid port number between 0 and 65535.

        Raises:
            ValueError: If the input is not a valid port number.
        """
        if 0 <= int(dst_port) <= 65535:
            self.FilteringDstPort = dst_port
        else:
            raise ValueError(f"The input param '{dst_port}' is an invalid identifier.")

    def to_dict(self):
        """
        Convert the object's attributes to a dictionary.

        Returns:
            dict: A dictionary containing all the attributes of the object.
        """
        return self.__dict__


class NetworkControlConfig:
    """NetworkControl"""

    def __init__(self, test_type):
        self.WaitPortsUpSecond = 30
        self.StartClientDelaySecond = 2
        self.ArpNsnaTimeoutSeconds = 30
        self.MessageSyncTimeoutSecond = 30
        self.MaxPortDownTime = 10
        self.NetworkCardUpTime = 5

        self.TimerSchedOutAction = "Warning"
        self.TCLRunMoment = "start"
        self.SendGratuitousArp = "yes"
        self.BcastNextMacOnlyFirstIP = "no"
        self.PingConnectivityCheck = "yes"
        self.PingTimeOutSecond = 15

        self.NetWork = "默认协议栈选项"
        self.IPChangeAlgorithm = "Increment"
        self.IPAddLoopPriority = "Client"
        self.PortChangeAlgorithm = "Increment"
        self.Layer4PortAddStep = 1

        self.IpPortMapping = "no"
        self.IpPortMappingTxt = ""
        self.Piggybacking = "yes"
        self.FlowRatio = "1:1"
        self.MaxEventPerLoop = 64
        self.TcpTimerSchedUsecond = 100
        self.MaxTimerPerLoop = 16
        self.TwotierByteStatistics = "no"
        self.Layer4PacketsCount = "no"
        self.SystemTimerDebug = "no"
        self.NicPhyRewrite = "yes"
        self.StopCloseAgeingSecond = 2
        self.TcpStopCloseMethod = "Reset"
        self.TcpPerfectClose = "no"
        self.PromiscuousMode = "no"
        self.TesterMessagePort = 2002

        if test_type in ["Rfc2544Latency"]:
            self.FPGARxMode = "packet"
            self.FPGATxMode = "segment"

    def set_wait_ports_up_second(self, seconds: int):
        self.WaitPortsUpSecond = seconds

    def set_start_client_delay(self, seconds: int):
        self.StartClientDelaySecond = seconds

    def set_arp_nsna_timeout(self, seconds: int):
        self.ArpNsnaTimeoutSeconds = seconds

    def set_message_sync_timeout(self, seconds: int):
        self.MessageSyncTimeoutSecond = seconds

    def set_max_port_down_time(self, seconds: int):
        self.MaxPortDownTime = seconds

    def set_network_card_up_time(self, seconds: int):
        self.NetworkCardUpTime = seconds

    def set_timer_sched_action(self, action: str):
        self.TimerSchedOutAction = action

    def set_tcl_run_moment(self, moment: str):
        self.TCLRunMoment = moment

    def set_send_gratuitous_arp(self, enable: bool):
        self.SendGratuitousArp = "yes" if enable else "no"

    def set_bcast_mac_policy(self, enable: bool):
        self.BcastNextMacOnlyFirstIP = "yes" if enable else "no"

    def set_ping_check(self, enable: bool):
        self.PingConnectivityCheck = "yes" if enable else "no"

    def set_ping_timeout(self, seconds: int):
        self.PingTimeOutSecond = seconds

    def set_network_stack(self, stack_name: str):
        self.NetWork = stack_name

    def set_ip_change_algo(self, algorithm: str):
        self.IPChangeAlgorithm = algorithm

    def set_ip_loop_priority(self, priority: str):
        self.IPAddLoopPriority = priority

    def set_port_change_algo(self, algorithm: str):
        self.PortChangeAlgorithm = algorithm

    def set_layer4_port_add_step(self, step: int):
        self.Layer4PortAddStep = step

    def set_ip_port_mapping(self, enable: bool):
        self.IpPortMapping = "yes" if enable else "no"

    def set_piggybacking(self, enable: bool):
        self.Piggybacking = "yes" if enable else "no"

    def set_flow_ratio(self, ratio: str):
        self.FlowRatio = ratio

    def set_max_event_per_loop(self, count: int):
        self.MaxEventPerLoop = count

    def set_tcp_timer_sched(self, microseconds: int):
        self.TcpTimerSchedUsecond = microseconds

    def set_max_timer_per_loop(self, count: int):
        self.MaxTimerPerLoop = count

    def set_twotier_byte_stats(self, enable: bool):
        self.TwotierByteStatistics = "yes" if enable else "no"

    def set_layer4_packets_count(self, enable: bool):
        self.Layer4PacketsCount = "yes" if enable else "no"

    def set_system_timer_debug(self, enable: bool):
        self.SystemTimerDebug = "yes" if enable else "no"

    def set_nic_phy_rewrite(self, enable: bool):
        self.NicPhyRewrite = "yes" if enable else "no"

    def set_stop_close_ageing(self, seconds: int):
        self.StopCloseAgeingSecond = seconds

    def set_tcp_stop_close_method(self, method: str):
        self.TcpStopCloseMethod = method

    def set_tcp_perfect_close(self, enable: bool):
        self.TcpPerfectClose = "yes" if enable else "no"

    def set_promiscuous_mode(self, enable: bool):
        self.PromiscuousMode = "yes" if enable else "no"

    def set_tester_message_port(self, port: int):
        self.TesterMessagePort = port

    # generate dict format
    def to_dict(self):
        return ToolsUtils.to_dict(self)


class BaseSubnet:

    def __init__(self, version, enable):
        """ Initialization of the basic parameters of the subnet
        Args:
            version (int): IP address version
            enable (str): Enable the subnet when yes, disable it when no
        """
        # Subnet enabled (default: yes)
        self.SubnetEnable = 'yes' if enable == 'yes' else 'no'
        # Subnet number (default: 1)
        self.SubnetNumber = '1' if version == 4 else '2'
        # IP address version
        self.SubnetVersion = "v4" if version == 4 else 'v6'
        # IP address range (default: 17.1.1.2+10)
        self.IpAddrRange = '17.1.1.2+10' if version == 4 else '3ffe:0:17:1::1:2+10'
        # Step value (default: 0.0.0.1)
        self.SubnetStep = '0.0.0.1' if version == 4 else '::1'
        # mask (default: 16)
        self.Netmask = '16' if version == 4 else '64'
        # Gateway address (default: #disabled)
        self.Gateway = '#disabled'
        # VLAN ID (default: 1#disabled)
        self.VlanID = '1#disabled'

    def to_dict(self):
        server_addr_format = getattr(self, "ServerAddressFormat", "")
        if server_addr_format == "IP":
            if hasattr(self, "SubnetServicePort"):
                delattr(self, "SubnetServicePort")
            if hasattr(self, "PeerServerSubnet"):
                delattr(self, "PeerServerSubnet")
        elif server_addr_format == "Port":
            if hasattr(self, "ServerIPRange"):
                delattr(self, "ServerIPRange")
        return self.__dict__

    @staticmethod
    def config_subnet_parameters(args, port_config_list, dut_role, proxy_mode):
        """Configure subnet parameters

        Args:
            args (tuple): The tuple of the subnet attribute dictionary to be configured
            port_config_list (list): The list of network port objects needs to be modified
            dut_role (str): Type of tested equipment
        """
        for arg_dict in args:
            for key, val_dict in arg_dict.items():
                port_name = key
                # Check whether the subnet configuration parameters are legal
                BaseSubnet.check_subnet_parameters_validity(val_dict)
                for port_config in port_config_list:
                    if port_config.Interface == port_name:
                        port_side = port_config.PortSide
                        network_subnets = port_config.NetworkSubnets
                        for network_subnet in network_subnets:
                            if network_subnet["SubnetNumber"] == val_dict["SubnetNumber"]:
                                # Modify the subnet configuration
                                BaseSubnet.check_subnet_parameters_to_be_modified(network_subnet, val_dict)
                                BaseSubnet.modify_subnet_parameters(network_subnet, val_dict)
                                break
                        else:
                            # Add subnet configuration
                            BaseSubnet.check_subnet_parameters_to_be_added(val_dict)
                            new_subnet_dict = BaseSubnet.add_subnet(dut_role, port_side, val_dict, proxy_mode)
                            port_config.NetworkSubnets.append(new_subnet_dict)
                        break

    @staticmethod
    def check_ip_address_validity(ip_addr_range):
        """ Check the legitimacy of the ip address

        Args:
            ip_addr_range (str): IP address range
        """
        for ip_addr in ip_addr_range.split(","):
            if ip_addr.find("+") != -1:
                ip_obj = ipaddress.ip_address(ip_addr.split("+")[0])
                if not ip_addr.split("+")[1].isdigit():
                    raise ValueError(f"{ip_addr} is not a valid IP address range")
            elif ip_addr.find("-") != -1:
                for ip_split in ip_addr.split("-"):
                    ip_obj = ipaddress.ip_address(ip_split)
            else:
                ip_obj = ipaddress.ip_address(ip_addr)
        return ip_obj.version

    @staticmethod
    def check_domain_validity(domain_name_range):
        """ Verify the legitimacy of the domain name
        Args:
            domain_name_range (str): Domain name string
        """
        import re
        for domain_name in domain_name_range.split(","):
            pattern = r"^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$"
            if not re.compile(pattern).match(domain_name):
                return False
        return True

    @staticmethod
    def check_subnet_parameter_name_validity(modify_dict):
        """ Check the legitimacy of the subnet parameter names

        Args:
            modify_dict (dict): The subnet configuration parameters to be modified
        """
        for item, val in modify_dict.items():
            legal_parameters = ['SubnetEnable', 'SubnetNumber', 'SubnetVersion', 'IpAddrRange', 'SubnetStep',
                                'Netmask', 'Gateway', 'VlanID', 'ServerAddressFormat', 'ServerIPRange',
                                'SubnetServicePort', 'PeerServerSubnet', 'ProxyIpAddrRange']
            if item not in legal_parameters:
                # Whether the subnet configuration parameter name is legal
                legal_parameters_str = ", ".join(legal_parameters)
                illegal_parameter_msg = f"The subnet configuration parameter name '{item}' is illegal, " \
                                        f"The legitimate subnet parameters include: {legal_parameters_str}"
                raise Exception(illegal_parameter_msg)

    @staticmethod
    def check_subnet_enable_value_validity(modify_dict, subnet_enable_val):
        """ The validity test of the value of the parameter 'SubnetEnable'

        Args:
            modify_dict (dict): The subnet configuration parameters to be modified
            subnet_enable_val (str): The value of the parameter 'SubnetEnable'
        """
        if not subnet_enable_val:
            # The default setting for subnet activation is 'yes'.
            modify_dict["SubnetEnable"] = 'yes'
        else:
            if subnet_enable_val not in ['yes', 'no']:
                raise ValueError(f"The value set by the parameter 'SubnetEnable' is illegal. The legal values are "
                                 f"'yes' or 'no'.")

    @staticmethod
    def check_subnet_number_is_exist(modify_dict):
        """ Check whether the subnet configuration parameters are legal

        Args:
            modify_dict (dict): The subnet configuration parameters to be modified
        """
        if "SubnetNumber" not in modify_dict:
            # The subnet number is a required field. Based on the subnet number, it is determined whether to modify or add a subnet
            raise ValueError("The subnet number is a required field. Based on the subnet number, "
                             "it is determined whether to modify or add a subnet")
        else:
            # Convert the value of the subnet number to a string type
            modify_dict["SubnetNumber"] = str(modify_dict["SubnetNumber"])
            if "PeerServerSubnet" in modify_dict:
                modify_dict["PeerServerSubnet"] = str(modify_dict["PeerServerSubnet"])

    @staticmethod
    def check_subnet_ip_addr_range_value_validity(modify_dict, ip_addr_range_val):
        """Check the legitimacy of the IP address range

        Args:
            modify_dict (dict): The subnet configuration parameters to be modified
            ip_addr_range_val (str): The value of the parameter 'IpAddrRange'
        """
        if not ip_addr_range_val:
            raise Exception('If you want to add a subnet, you need to specify the "IpAddrRange" parameter')
        if ip_addr_range_val:
            subnet_version = BaseSubnet.check_ip_address_validity(ip_addr_range_val)
            modify_dict["SubnetVersion"] = "v4" if subnet_version == 4 else "v6"

    @staticmethod
    def check_subnet_parameters_validity(modify_dict):
        """ Check whether the subnet configuration parameters are legal

        Args:
            modify_dict (dict): The subnet configuration parameters to be modified
        """
        # 1. Whether the subnet configuration parameter name is legal
        BaseSubnet.check_subnet_parameter_name_validity(modify_dict)

        # 2. Make a legality judgment on the values of the subnet attributes
        BaseSubnet.check_subnet_enable_value_validity(modify_dict, modify_dict.get("SubnetEnable", ""))

        # 3. Determine whether there is a subnet number parameter
        BaseSubnet.check_subnet_number_is_exist(modify_dict)

    @staticmethod
    def check_subnet_parameters_to_be_added(modify_dict):
        # 4. Check the legitimacy of the IP address range
        BaseSubnet.check_subnet_ip_addr_range_value_validity(modify_dict, modify_dict.get("IpAddrRange", ""))

    @staticmethod
    def check_subnet_parameters_to_be_modified(old_dict, modify_dict):
        if "SubnetServicePort" in modify_dict and "ServerIPRange" not in modify_dict:
            modify_dict["ServerAddressFormat"] = "Port"
            if not modify_dict.get("PeerServerSubnet", ""):
                raise Exception("If the server type is tester port, the server subnet number needs to be specified.")
            if "ServerIPRange" in old_dict:
                del old_dict["ServerIPRange"]
        if "ServerIPRange" in modify_dict and "SubnetServicePort" not in modify_dict:
            server_ip_range = modify_dict["ServerIPRange"]
            try:
                BaseSubnet.check_ip_address_validity(server_ip_range)
                modify_dict["ServerAddressFormat"] = "IP"
            except ValueError:
                check_out = BaseSubnet.check_domain_validity(server_ip_range)
                if not check_out:
                    raise ValueError(
                        f"The value of the server IP address or domain name '{server_ip_range}' is invalid")
                modify_dict["ServerAddressFormat"] = "Domain"
            if "SubnetServicePort" in old_dict:
                del old_dict["SubnetServicePort"]
            if "PeerServerSubnet" in old_dict:
                del old_dict["PeerServerSubnet"]

    @staticmethod
    def modify_subnet_parameters(old_dict, modify_dict):
        old_dict.update(modify_dict)

    @staticmethod
    def add_subnet(dut_role, port_side, modify_dict, proxy_mode=''):
        if "IpAddrRange" not in modify_dict:
            raise ValueError("If you want to add a subnet, specify 'IpAddrRange' parameters")
        if port_side == "client":
            new_subnet_dict = ClientSubnet.add_client_subnet(dut_role, proxy_mode, modify_dict)
        else:
            new_subnet_dict = ServerSubnet.add_server_subnet(modify_dict)
        return new_subnet_dict


class ClientSubnet(BaseSubnet):
    ipv4_occurs_num = 1
    ipv6_occurs_num = 1

    def __init__(self, dut_role='Gateway', proxy_mode='Reverse', version=4, enable='yes', server_address_format='IP', test_type=""):
        """ Initialize the parameters of the client subnet.
        Args:
            dut_role (str): Type of the tested equipment
            proxy_mode (str): When the type of the tested device is a proxy device, the proxy mode requires specification.
            version (int): IP address version
            enable (str): Enable the subnet when yes, disable it when no
        """
        super(ClientSubnet, self).__init__(version, enable)

        # IP address range (default: 17.1.1.2+10)
        if version == 4:
            self.IpAddrRange = '17.{}.2.2+100'.format(self.ipv4_occurs_num)
        else:
            self.IpAddrRange = '3ffe:0:17:{}::2:2+100'.format(self.ipv6_occurs_num)

        # Server type (default: IP)
        self.ServerAddressFormat = server_address_format

        # Server IP address or domain name (default: 17.1.1.2+10)
        if version == 4:
            self.ServerIPRange = '17.{}.1.2+10'.format(self.ipv4_occurs_num)
            ClientSubnet.ipv4_occurs_num += 1
        else:
            self.ServerIPRange = '3ffe:0:17:{}::1:2+10'.format(self.ipv6_occurs_num)
            ClientSubnet.ipv6_occurs_num += 1

        # When the server type is selected as "Port", specify the server port and the server subnet number
        self.SubnetServicePort = 'port2'
        if version == 4:
            self.PeerServerSubnet = '1'
        else:
            self.PeerServerSubnet = '2'
        self.SubnetRole = 'client'
        if dut_role == "Proxy":
            # The proxy mode should incorporate the IP address of the proxy service.
            self.ProxyIpAddrRange = ''
            if proxy_mode == "Reverse":
                # The reverse proxy mode does not require specifying the server parameters
                del self.ServerAddressFormat
                del self.ServerIPRange
                del self.SubnetServicePort
                del self.PeerServerSubnet

    @staticmethod
    def add_client_subnet(dut_role, proxy_mode, new_subnet_dict):
        # Except for the reverse proxy mode, clients of other modes need to specify the server type.
        if not (dut_role == 'Proxy' and proxy_mode == "Reverse"):
            if "ServerIPRange" not in new_subnet_dict and "SubnetServicePort" not in new_subnet_dict:
                raise ValueError(
                    "If you want to add a subnet for the client role, specify the server IP address or server port")
            if "SubnetServicePort" in new_subnet_dict and "PeerServerSubnet" not in new_subnet_dict:
                raise ValueError("If the parameter 'SubnetServicePort' is specified, the parameter 'PeerServerSubnet' "
                                 "must be specified")

        server_address_format = "IP" if "ServerIPRange" in new_subnet_dict else "Port"
        new_subnet_dict["ServerAddressFormat"] = server_address_format

        if new_subnet_dict["SubnetVersion"] == "v4":
            default_subnet_dict = ClientSubnet(dut_role, proxy_mode,
                                               server_address_format=server_address_format).to_dict()
        else:
            default_subnet_dict = ClientSubnet(dut_role, proxy_mode, 6, enable="yes",
                                               server_address_format=server_address_format).to_dict()

        # Set default values for subnet attributes
        default_subnet_dict.update(new_subnet_dict)
        return default_subnet_dict


class ServerSubnet(BaseSubnet):
    ipv4_occurs_num = 1
    ipv6_occurs_num = 1

    def __init__(self, version=4, enable='yes'):
        super(ServerSubnet, self).__init__(version, enable)
        # IP address range (default: 17.1.1.2+10)
        if version == 4:
            self.IpAddrRange = '17.{}.1.2+10'.format(self.ipv4_occurs_num)
            ServerSubnet.ipv4_occurs_num += 1
        else:
            self.IpAddrRange = '3ffe:0:17:{}::1:2+10'.format(self.ipv6_occurs_num)
            ServerSubnet.ipv6_occurs_num += 1
        # Subnet role
        self.SubnetRole = 'server'

    @staticmethod
    def add_server_subnet(new_subnet_dict):
        if new_subnet_dict["SubnetVersion"] == "v4":
            default_subnet_dict = ServerSubnet().to_dict()
        else:
            default_subnet_dict = ServerSubnet(6, enable="yes").to_dict()
        default_subnet_dict.update(new_subnet_dict)
        return default_subnet_dict


# Define a header checksum configuration class for managing the header checksum types of IPV4, TCP, and UDP
class HeadChecksumConf:
    def __init__(self, IPV4HeadChecksumType="auto", TCPHeadChecksumType="auto", UDPHeadChecksumType="auto"):
        """
        Initialize the header checksum configuration class.

        Args:
            IPV4HeadChecksumType (str, optional): IPV4 head check type, default value: "auto".
            TCPHeadChecksumType (str, optional): TCP head check type, default value: "auto".
            UDPHeadChecksumType (str, optional): UDP head check type, default value: "auto".
        """
        self.IPV4HeadChecksumType = IPV4HeadChecksumType
        self.TCPHeadChecksumType = TCPHeadChecksumType
        self.UDPHeadChecksumType = UDPHeadChecksumType

    def to_dict(self):
        """
        Convert the header checksum configuration to a dictionary.

        Returns:
            dict: containing the checksum types of IPV4, TCP and UDP headers.
        """
        return {
            "IPV4HeadChecksumType": self.IPV4HeadChecksumType,
            "TCPHeadChecksumType": self.TCPHeadChecksumType,
            "UDPHeadChecksumType": self.UDPHeadChecksumType
        }


# Define the Network Interface Card (NIC) configuration class to manage various configurations of the NIC
class NICConfiguration:
    def __init__(self):
        """
        Initialize the network interface card configuration class and set the default configurations for each item.
        """
        self.MacMasquerade = "A2:01#disabled"
        self.PortSpeedDetectMode = "Autoneg"
        self.PortRXRSS = "no"
        self.nictype = "PERF"
        self.receivequeue = "4"
        self.nb_txd = 4096
        self.nb_rxd = 4096
        self.NextPortMacMethod = "ARP_NSNA#disabled"
        self.sendqueue = "4"
        self.device = "NetiTest IT2X010GF47LA 1G/10G SmartNIC"
        self.TesterPortMacAddress = "68:91:d0:66:b1:b6#disabled"
        # Initialize the header checksum configuration
        self.HeadChecksumConf = HeadChecksumConf()

    def to_dict(self):
        """
        Convert the network interface card configuration to a dictionary.

        Returns:
            dict: It contains all the configuration information of NIC
        """
        return {
            "MacMasquerade": self.MacMasquerade,
            "PortSpeedDetectMode": self.PortSpeedDetectMode,
            "PortRXRSS": self.PortRXRSS,
            "nictype": self.nictype,
            "receivequeue": self.receivequeue,
            "nb_txd": self.nb_txd,
            "nb_rxd": self.nb_rxd,
            "NextPortMacMethod": self.NextPortMacMethod,
            "sendqueue": self.sendqueue,
            "device": self.device,
            "TesterPortMacAddress": self.TesterPortMacAddress,
            "HeadChecksumConf": self.HeadChecksumConf.to_dict()
        }

    def to_json(self, indent=4):
        """
        Convert the NICConfiguration instance to a string in JSON format.

        Args:
        indent (int, optional): The number of indent Spaces in a JSON string, with a default of 4.

        Returns:
        str: A JSON format string containing NICConfiguration configuration information.
        """
        return json.dumps(self.to_dict(), indent=indent)


class GTPUTunnel:
    """
    Represents the configuration class for GTPU encapsulation tunnels, used to manage various parameters of GTPU tunnels.
    """

    def __init__(self):
        """
        Initialize an instance of the GTPUTunnel class and set the default GTPU tunnel parameters.
        """
        self.GTPUEnable = "no"  # Indicates whether the GTPU tunnel is enabled
        self.TunnelIPVersion = 4  # The IP version used by the tunnel, default is IPv4
        self.TunnelPort1 = 2152  # Local GTPU tunnel port
        self.TunnelTeid1 = 1  # Remote GTPU tunnel starting ID
        self.TunnelQfi = 1  # GTPU extension header value
        self.TunnelIPAddr1 = "172.1.1.2"  # Local GTPU IP address
        self.TunnelIPAddr2 = "172.1.2.2"  # Remote GTPU IP address
        self.GtpuNetworkMask = 16  # GTPU network mask

    def set_gtpu_enable(self, enable: bool):
        """
        Set the enable status of the GTPU tunnel.

        Args:
            enable (bool): If True, enable the GTPU tunnel; if False, disable it.
        """
        self.GTPUEnable = "yes" if enable else "no"

    def set_tunnel_ip_version(self, version: int):
        """
        Set the IP version used by the GTPU tunnel.

        Args:
            version (int): The IP version to be set, must be 4 or 6.

        Raises:
            ValueError: Thrown when the incoming IP version is not 4 or 6.
        """
        if version in (4, 6):
            self.TunnelIPVersion = version
        else:
            raise ValueError("Only IP version 4 or 6 is supported.")

    def set_tunnel_port(self, port: int):
        """
        Set the port number of the GTPU tunnel.

        Args:
            port (int): The port number to be set.
        """
        self.TunnelPort1 = port

    def set_tunnel_teid(self, teid: int):
        """
        Set the remote GTPU tunnel starting ID.

        Args:
            teid (int): The TEID to be set.
        """
        self.TunnelTeid1 = teid

    def set_tunnel_qfi(self, qfi: int):
        """
        Set the GTPU extension header value.

        Args:
            qfi (int): The QFI to be set.
        """
        self.TunnelQfi = qfi

    def set_tunnel_ip_local(self, ip1: str):
        """
        Set the local IP address of the GTPU tunnel.

        Args:
            ip1 (str): The first IP address.
            ip2 (str): The second IP address.
        """
        self.TunnelIPAddr1 = ip1

    def set_tunnel_ip_local(self, ip2: str):
        """
        Set the remote IP address of the GTPU tunnel.

        Args:
            ip2 (str): The first IP address.
        """
        self.TunnelIPAddr1 = ip2

    def set_network_mask(self, mask: int):
        """
        Set the GTPU network mask.

        Args:
            mask (int): The network mask to be set, must be between 0 and 32.

        Raises:
            ValueError: Thrown when the incoming network mask is not between 0 and 32.
        """
        if 0 <= mask <= 32:
            self.GtpuNetworkMask = mask
        else:
            raise ValueError("Invalid network mask, must be between 0 and 32.")

    def to_dict(self):
        """
        Convert the attributes of the GTPUTunnel instance to a dictionary.

        Returns:
            dict: A dictionary containing the GTPU tunnel configuration information.
        """
        return self.__dict__


class VXLANTunnel:
    """
    A configuration class representing a VXLAN tunnel, used to manage various parameters of the VXLAN tunnel.
    """

    def __init__(self):
        """
        Initializes an instance of the VXLANTunnel class, setting default VXLAN tunnel parameters.
        """
        self.SrcVTEPIPAddr = "192.168.1.2"  # Source VTEP IP address
        self.StartVniID = 10  # Starting VNI identifier
        self.VXLANVlanID = "1#disabled"  # VXLAN VLAN ID
        self.VTEPIPNetmask = "16"  # VTEP IP network mask
        self.VXLANEnable = "no"  # Indicates whether the VXLAN tunnel is enabled
        self.VlanIDStep = "1#disabled"  # VLAN ID step size
        self.VTEPDstMac = "68:91:d0:01:01:01#disabled"  # Destination VTEP MAC address
        self.StepVniID = 10  # VNI identifier step size
        self.VTEPIPVersion = 4  # IP version used by the VTEP, default is IPv4
        self.VniIdCount = 10  # Number of VNI identifiers
        self.DstVTEPIPAddr = "192.168.2.2"  # Destination VTEP IP address
        self.TunnelCount = 1  # Number of tunnels

    def set_src_vtep_ip(self, ip: str):
        """
        Sets the source VTEP IP address.

        Args:
            ip (str): The source VTEP IP address to set.
        """
        self.SrcVTEPIPAddr = ip

    def set_dst_vtep_ip(self, ip: str):
        """
        Sets the destination VTEP IP address.

        Args:
            ip (str): The destination VTEP IP address to set.
        """
        self.DstVTEPIPAddr = ip

    def set_start_vni_id(self, vni: int):
        """
        Sets the starting VNI identifier.

        Args:
            vni (int): The starting VNI identifier to set.
        """
        self.StartVniID = vni

    def set_vxlan_vlan_id(self, vlan_id: str):
        """
        Sets the VXLAN VLAN ID.

        Args:
            vlan_id (str): The VLAN ID to set.
        """
        self.VXLANVlanID = vlan_id

    def set_vtep_netmask(self, netmask: str):
        """
        Sets the VTEP IP network mask.

        Args:
            netmask (str): The network mask to set.
        """
        self.VTEPIPNetmask = netmask

    def set_vxlan_enable(self, enable: bool):
        """
        Sets the VXLAN tunnel enable status.

        Args:
            enable (bool): If True, the VXLAN tunnel is enabled; if False, it is disabled.
        """
        self.VXLANEnable = "yes" if enable else "no"

    def set_vlan_id_step(self, step: str):
        """
        Sets the VLAN ID step size.

        Args:
            step (str): The VLAN ID step size to set.
        """
        self.VlanIDStep = step

    def set_vtep_dst_mac(self, mac: str):
        """
        Sets the destination VTEP MAC address.

        Args:
            mac (str): The destination VTEP MAC address to set.
        """
        self.VTEPDstMac = mac

    def set_step_vni_id(self, step: int):
        """
        Sets the VNI identifier step size.

        Args:
            step (int): The VNI identifier step size to set.
        """
        self.StepVniID = step

    def set_vtep_ip_version(self, version: int):
        """
        Sets the IP version used by the VTEP.

        Args:
            version (int): The IP version to set, must be either 4 or 6.

        Raises:
            ValueError: Raised when the provided IP version is neither 4 nor 6.
        """
        if version in (4, 6):
            self.VTEPIPVersion = version
        else:
            raise ValueError("Only IP version 4 or 6 is supported.")

    def set_vni_id_count(self, count: int):
        """
        Sets the number of VNI identifiers.

        Args:
            count (int): The number of VNI identifiers to set.
        """
        self.VniIdCount = count

    def set_tunnel_count(self, count: int):
        """
        Sets the number of tunnels.

        Args:
            count (int): The number of tunnels to set.
        """
        self.TunnelCount = count

    def to_dict(self):
        """
        Converts the VXLANTunnel instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing the VXLAN tunnel configuration.
        """
        return self.__dict__


class QoSConfiguration:
    """
    A class representing QoS configuration, used to manage various QoS-related parameters.
    """

    def __init__(self):
        """
        Initializes an instance of the QoSConfiguration class, setting default QoS configuration parameters.
        """
        self.RoCEv2PFCMode = "no"  # Whether RoCEv2 PFC mode is enabled
        self.VlanPriority = "3"  # VLAN priority
        self.IPDscpPriority = "24"  # IP DSCP priority
        self.ECN = "00"  # ECN field value
        self.RoCEv2PFCList = "0,0,0,0,1,0,0,0"  # RoCEv2 PFC list
        self.PriorityEnable = "DscpBased"  # Priority enable mode

    def set_roce_pfc_mode(self, enable: bool):
        """
        Sets the enable status of RoCEv2 PFC mode.

        Args:
            enable (bool): If True, enables RoCEv2 PFC mode; if False, disables it.
        """
        self.RoCEv2PFCMode = "yes" if enable else "no"

    def set_vlan_priority(self, priority: str):
        """
        Sets the VLAN priority.

        Args:
            priority (str): The VLAN priority to set.
        """
        self.VlanPriority = priority

    def set_ip_dscp_priority(self, dscp: str):
        """
        Sets the IP DSCP priority.

        Args:
            dscp (str): The IP DSCP priority to set.
        """
        self.IPDscpPriority = dscp

    def set_ecn(self, ecn: str):
        """
        Sets the ECN field value.

        Args:
            ecn (str): The ECN field value to set, must be a 2-digit hexadecimal string.

        Raises:
            ValueError: If the provided ECN field value is not a 2-digit hexadecimal string.
        """
        if len(ecn) == 2 and all(c in "0123456789ABCDEFabcdef" for c in ecn):
            self.ECN = ecn.upper()
        else:
            raise ValueError("ECN must be a 2-digit hex string (e.g., '00', '01', ..., 'FF').")

    def set_roce_pfc_list(self, pfc_list: str):
        """
        Sets the RoCEv2 PFC list.

        Args:
            pfc_list (str): The RoCEv2 PFC list to set, must be 8 comma-separated '0' or '1'.

        Raises:
            ValueError: If the provided RoCEv2 PFC list does not meet the format requirements.
        """
        parts = pfc_list.split(",")
        if len(parts) != 8 or not all(p in ("0", "1") for p in parts):
            raise ValueError("RoCEv2PFCList must be 8 comma-separated values of '0' or '1'.")
        self.RoCEv2PFCList = pfc_list

    def set_priority_enable(self, mode: str):
        """
        Sets the priority enable mode.

        Args:
            mode (str): The priority enable mode to set, must be one of 'DscpBased', 'None', or 'VlanBased'.

        Raises:
            ValueError: If the provided mode is not 'DscpBased', 'None', or 'VlanBased'.
        """
        if mode in ("DscpBased", "None", "VlanBased"):
            self.PriorityEnable = mode
        else:
            raise ValueError("PriorityEnable must be one of 'DscpBased', 'VlanBased', or 'None'.")

    def to_dict(self):
        """
        Converts the QoSConfiguration instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing the QoS configuration.
        """
        return self.__dict__


class MACSEC:
    """
    A class representing MACsec configuration, used to manage various MACsec-related parameters.
    """

    def __init__(self):
        """
        Initializes an instance of the MACSEC class, setting default MACsec configuration parameters.
        """
        self.MACSECEnable = "no"  # Whether MACsec is enabled
        self.CAK_VALUE = "000102030405060708090a0b0c0d0e0f"  # CAK value
        self.macsec_PN = 1  # MACsec PN value
        self.macsec_cipher_suite = "gcm-aes-128"  # Cipher suite used by MACsec
        self.CAK_NAME = "1"  # CAK name
        self.SCI_MAC = "001122334455"  # SCI MAC address
        self.PORT_Identifer = 1  # Port identifier

    def set_macsec_enable(self, enable: bool):
        """
        Sets the enable status of MACsec.

        Args:
            enable (bool): If True, enables MACsec; if False, disables it.
        """
        self.MACSECEnable = "yes" if enable else "no"

    def set_cak_value(self, cak: str):
        """
        Sets the CAK value.

        Args:
            cak (str): The CAK value to set, must be a 32-character hexadecimal string.

        Raises:
            ValueError: If the provided CAK value is not a 32-character hexadecimal string.
        """
        if len(cak) == 32 and all(c in "0123456789abcdefABCDEF" for c in cak):
            self.CAK_VALUE = cak.lower()
        else:
            raise ValueError("CAK_VALUE must be a 128-bit (32 hex chars) hex string.")

    def set_cak_name(self, name: str):
        """
        Sets the CAK name.

        Args:
            name (str): The CAK name to set.
        """
        self.CAK_NAME = name

    def set_cipher_suite(self, suite: str):
        """
        Sets the cipher suite used by MACsec.

        Args:
            suite (str): The cipher suite to set, must be either 'gcm-aes-128' or 'gcm-aes-256'.

        Raises:
            ValueError: If the provided cipher suite is not supported.
        """
        if suite in ("gcm-aes-128", "gcm-aes-256"):
            self.macsec_cipher_suite = suite
        else:
            raise ValueError("Unsupported cipher suite.")

    def set_sci_mac(self, mac: str):
        """
        Sets the SCI MAC address.

        Args:
            mac (str): The SCI MAC address to set, must be a 12-character hexadecimal string.

        Raises:
            ValueError: If the provided SCI MAC address is not a 12-character hexadecimal string.
        """
        if len(mac) == 12 and all(c in "0123456789abcdefABCDEF" for c in mac):
            self.SCI_MAC = mac.lower()
        else:
            raise ValueError("SCI_MAC must be a 12-character hex MAC address without separators.")

    def set_port_identifier(self, port: int):
        """
        Sets the port identifier.

        Args:
            port (int): The port identifier to set.
        """
        self.PORT_Identifer = port

    def set_pn(self, pn: int):
        """
        Sets the MACsec PN value.

        Args:
            pn (int): The PN value to set.
        """
        self.macsec_PN = pn

    def to_dict(self):
        """
        Converts the MACSEC instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing the MACsec configuration information.
        """
        return self.__dict__


class AdditionalFields:
    """
    A class representing AdditionalFields configuration, used to manage various AdditionalFields parameters.
    """

    def __init__(self, port_name):
        self.Bgp = {
            "BgpTabEnable": "yes",
            "DownwardNetworkZoneCount": 8,
            "BGPv4Version": 1,
            "simPeCount": 1,
            "BgpRouterKeepAliveInter": 60,
            "BgpRouterNumber": 200,
            "BgpDUT": 100,
            "BGPLoopbackAddress": "13.1.1.10",
            "BGPRouterID": "2.2.2.2",
            "peerAddress": "13.1.1.1",
            "PortSide": "server"
        }

    def set_bgp(self, value):
        self.Bgp.update(value)

    @staticmethod
    def config_additional_fields_parameters(args, port_config_list):
        """Configure Additional fields parameters

        Args:
            args (tuple): The tuple of the subnet attribute dictionary to be configured
            port_config_list (list): The list of network port objects needs to be modified
            dut_role (str): Type of tested equipment
        """
        for arg_dict in args:
            for key, val_dict in arg_dict.items():
                port_name = key
                for port_config in port_config_list:
                    if port_config.Interface == port_name:

                        # set empty, The default values cannot be used
                        if not val_dict:
                            port_config.AdditionalFields = {}
                            break

                        port_config.AdditionalFields.update(val_dict)

    def to_dict(self):
        """
        Converts the MACSEC instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing the MACsec configuration information.
        """
        return self.__dict__


class RouteStrmCfg:
    """
    A class representing BGP RouteStrmCfg configuration, used to manage various RouteStrmCfg parameters.
    """

    def __init__(self):
        self.IP_Version = "V4"
        self.rt_strm_dst_port = "6000/0"
        self.rt_strm_dst_port_mode = "single"
        self.rt_strm_enable = "no"
        self.rt_strm_mode = "to_one"
        self.rt_strm_src = "Emu"
        self.rt_strm_src_port = "10000/0"
        self.rt_strm_src_port_mode = "single"
        self.rt_strm_target = "peer_port_emu"
        self.strm_appoint_ip = "17.1.1.3+10/0.0.1.0"
        self.strm_dst_ip = "65.1.1.3+10/0.0.1.0"

    def set_ip_version(self, value):
        self.IP_Version = value

    def set_rt_strm_dst_port(self, value):
        self.rt_strm_dst_port = value

    def set_rt_strm_dst_port_mode(self, value):
        self.rt_strm_dst_port_mode = value

    def set_rt_strm_enable(self, value):
        self.rt_strm_enable = value

    def set_rt_strm_mode(self, value):
        self.rt_strm_mode = value

    def set_rt_strm_src(self, value):
        self.rt_strm_src = value

    def set_rt_strm_src_port(self, value):
        self.rt_strm_src_port = value

    def set_rt_strm_src_port_mode(self, value):
        self.rt_strm_src_port_mode = value

    def set_rt_strm_target(self, value):
        self.rt_strm_target = value

    def set_strm_appoint_ip(self, value):
        self.strm_appoint_ip = value

    def set_strm_dst_ip(self, value):
        self.strm_dst_ip = value

    def to_dict(self):
        """
        Converts the MACSEC instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing the MACsec configuration information.
        """
        return self.__dict__


class BfdConfig:
    """
    A class representing BGP RouteStrmCfg configuration, used to manage various RouteStrmCfg parameters.
    """

    def __init__(self):
        self.bfd_enable = "no"

    def set_strm_dst_ip(self, value):
        self.bfd_enable = value

    def to_dict(self):
        """
        Converts the MACSEC instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing the MACsec configuration information.
        """
        return self.__dict__


class MsgFragSet:
    """
    A class for IP packet fragmentation settings, used to manage parameters related to message fragmentation.
    """

    def __init__(self):
        """
        Initializes an instance of the MsgFragSet class, setting default message fragmentation settings.
        """
        self.IPv6FragEnable = "no"  # Whether IPv6 fragmentation is enabled
        self.IPv6UDPEnable = "no"  # Whether IPv6 UDP is enabled
        self.PccketFragmentDisorder = "no"  # Whether packet fragmentation disorder is enabled
        self.IPv4UDPEnable = "no"  # Whether IPv4 UDP is enabled
        self.PortMTU = "1500"  # Port MTU value
        self.PccketFragmentHeadpkt = "no"  # Whether only the first fragment is enabled
        self.MTUCoverEnable = "no"  # Whether MTU coverage is enabled
        self.IPv6TCPMSS = "100"  # IPv6 TCP MSS value
        self.PccketFragmentOverlap = "no"  # Whether packet fragmentation overlap is enabled
        self.IPv4FragEnable = "no"  # Whether IPv4 fragmentation is enabled
        self.IPv4TCPMSS = "1460"  # IPv4 TCP MSS value

    def set_ipv6_frag_enable(self, enable: bool):
        """
        Sets the enable status of IPv6 fragmentation.

        Args:
            enable (bool): If True, enables IPv6 fragmentation; if False, disables it.
        """
        self.IPv6FragEnable = "yes" if enable else "no"

    def set_ipv6_udp_enable(self, enable: bool):
        """
        Sets the enable status of IPv6 UDP.

        Args:
            enable (bool): If True, enables IPv6 UDP; if False, disables it.
        """
        self.IPv6UDPEnable = "yes" if enable else "no"

    def set_ipv4_frag_enable(self, enable: bool):
        """
        Sets the enable status of IPv4 fragmentation.

        Args:
            enable (bool): If True, enables IPv4 fragmentation; if False, disables it.
        """
        self.IPv4FragEnable = "yes" if enable else "no"

    def set_ipv4_udp_enable(self, enable: bool):
        """
        Sets the enable status of IPv4 UDP.

        Args:
            enable (bool): If True, enables IPv4 UDP; if False, disables it.
        """
        self.IPv4UDPEnable = "yes" if enable else "no"

    def set_packet_disorder(self, enable: bool):
        """
        Sets the enable status of packet fragmentation disorder.

        Args:
            enable (bool): If True, enables packet fragmentation disorder; if False, disables it.
        """
        self.PccketFragmentDisorder = "yes" if enable else "no"

    def set_packet_headpkt(self, enable: bool):
        """
        Sets the enable status of first fragment only.

        Args:
            enable (bool): If True, enables first fragment only; if False, disables it.
        """
        self.PccketFragmentHeadpkt = "yes" if enable else "no"

    def set_packet_overlap(self, enable: bool):
        """
        Sets the enable status of packet fragmentation overlap.

        Args:
            enable (bool): If True, enables packet fragmentation overlap; if False, disables it.
        """
        self.PccketFragmentOverlap = "yes" if enable else "no"

    def set_mtu_cover_enable(self, enable: bool):
        """
        Sets the enable status of MTU coverage.

        Args:
            enable (bool): If True, enables MTU coverage; if False, disables it.
        """
        self.MTUCoverEnable = "yes" if enable else "no"

    def set_port_mtu(self, mtu: int):
        """
        Sets the port MTU value.

        Args:
            mtu (int): The port MTU value to set, must be a positive integer.

        Raises:
            ValueError: If the provided MTU value is not a positive integer.
        """
        if mtu > 0:
            self.PortMTU = mtu
        else:
            raise ValueError("MTU must be a positive integer.")

    def set_ipv4_tcp_mss(self, mss: str):
        """
        Sets the IPv4 TCP MSS value.

        Args:
            mss (str): The IPv4 TCP MSS value to set.
        """
        self.IPv4TCPMSS = mss

    def set_ipv6_tcp_mss(self, mss: str):
        """
        Sets the IPv6 TCP MSS value.

        Args:
            mss (str): The IPv6 TCP MSS value to set.
        """
        self.IPv6TCPMSS = mss

    def to_dict(self):
        """
        Converts the MsgFragSet instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing message fragmentation settings.
        """
        return self.__dict__


class Vlan:
    """
    A class representing VLAN configuration, used to manage parameters related to VLAN.
    """

    def __init__(self):
        """
        Initializes an instance of the Vlan class, setting default VLAN configuration parameters.
        """
        self.OuterVlanID = "1#disabled"  # Outer VLAN ID
        self.QinqType = "0x88A8#disabled"  # QinQ type
        self.VlanID = "1#disabled"  # VLAN ID

    def set_outer_vlan_id(self, vlan_id: str):
        """
        Sets the outer VLAN ID.

        Args:
            vlan_id (str): The outer VLAN ID to set.
        """
        self.OuterVlanID = vlan_id

    def set_qinq_type(self, qinq: str):
        """
        Sets the QinQ type.

        Args:
            qinq (str): The QinQ type to set, must be a hexadecimal string starting with '0x'.

        Raises:
            ValueError: If the provided QinQ type doesn't start with '0x'.
        """
        if not qinq.startswith("0x"):
            raise ValueError("QinqType should be a hex string starting with '0x'")
        self.QinqType = qinq

    def set_vlan_id(self, vlan_id: str):
        """
        Sets the VLAN ID.

        Args:
            vlan_id (str): The VLAN ID to set.
        """
        self.VlanID = vlan_id

    def to_dict(self):
        """
        Converts the Vlan instance attributes to a dictionary.

        Returns:
            dict: A dictionary containing VLAN configuration information.
        """
        return self.__dict__


class VirtualRouterConfigDict:
    def __init__(self, enable=False, version="v4", protocol="Static", ip_addr="", mask="", next_hop="",
                 side="client", test_type=""):
        self.VirtualRouterEnable = "yes" if enable else "no"
        self.SubnetNumber = "1" if version == "v4" else "2"
        self.SubnetVersion = version

        # set default values by net version
        if version == "v4":
            if test_type in ["BGPv4"]:
                self.VirtualRouterEnable = "yes"
                self.VirtualRouterIPAddr = "17.0.0.3"
                self.VirtualRouterMask = mask or "16"
                self.VirtualRouterNextHop = "13.1.1.1"
                self.DownwardNetworkZoneCount = 8
            else:
                self.VirtualRouterIPAddr = ip_addr or ("17.0.0.2" if side == "client" else "17.0.0.3")
                self.VirtualRouterMask = mask or "16"
                self.VirtualRouterNextHop = next_hop or "17.0.0.1#disabled"
        else:
            self.VirtualRouterIPAddr = ip_addr or ("3ffe:0:17:0::1:2" if side == "client" else "3ffe:0:17:0::1:3")
            self.VirtualRouterMask = mask or "64"
            self.VirtualRouterNextHop = next_hop or "3ffe:0:17:0::1:1#disabled"

        self.VirtualRouterProtocol = protocol

    def set_enable(self, enable: bool):
        self.VirtualRouterEnable = "yes" if enable else "no"

    def set_protocol(self, protocol: str):
        self.VirtualRouterProtocol = protocol

    def set_ip_address(self, ip: str):
        self.VirtualRouterIPAddr = ip

    def set_next_hop(self, hop: str):
        self.VirtualRouterNextHop = hop

    def set_downward_network_zone_count(self, value):
        self.VirtualRouterNextHop = value

    @staticmethod
    def config_virtual_router_parameters(args, port_config_list):
        """Configure virtual router parameters

        Args:
            args (tuple): The tuple of the subnet attribute dictionary to be configured
            port_config_list (list): The list of network port objects needs to be modified
            dut_role (str): Type of tested equipment
        """
        for arg_dict in args:
            for key, val_dict in arg_dict.items():
                port_name = key
                for port_config in port_config_list:
                    if port_config.Interface == port_name:

                        # set empty, The default values cannot be used
                        if not val_dict:
                            port_config.VirtualRouterConfig = []
                            break

                        virtual_router_config = port_config.VirtualRouterConfig
                        for virtual_router_config_dict in virtual_router_config:
                            if virtual_router_config_dict["SubnetNumber"] == val_dict["SubnetNumber"]:
                                # Modify configuration
                                virtual_router_config_dict.update(val_dict)
                                break

    def to_dict(self):
        return self.__dict__


class VirtualRouterConfig:
    """
    * VirtualRouterConfig Class
    """

    def __init__(self, config_list=[], side="client", test_type="", port_name=""):
        self.side = side
        if not config_list:
            v4_config = VirtualRouterConfigDict(version="v4", side=side, test_type=test_type)
            config_list.append(v4_config)

            if test_type not in ["BGPv4"]:
                v6_config = VirtualRouterConfigDict(version="v6", side=side)
                config_list.append(v6_config)

        self.config_list = config_list  # list of VirtualRouterConfigDict objects

    def set_config(self, index, config_dict):
        if index < 0 or index >= len(self.config_list):
            raise IndexError("Index out of range")
        self.config_list[index] = config_dict

    def add_config(self, config_dict):
        self.config_list.append(config_dict)
        for index, item in enumerate(self.config_list):
            item.SubnetNumber = str(index + 1)

    def remove_config(self, index):
        if index < 0 or index >= len(self.config_list):
            raise IndexError("Index out of range")
        del self.config_list[index]
        for index, item in enumerate(self.config_list):
            item.SubnetNumber = str(index + 1)

    def get_configs(self):
        return self.config_list

    def to_dict(self):
        return [config.to_dict() for config in self.config_list]


class NetworkZone:
    """
    * NetworkZone Class
    """

    def __init__(self, network_zone_list=[], test_type=""):
        if not network_zone_list:
            if test_type in ["BGPv4"]:
                ipv4_zone = NetworkZoneDict(version="v4")
                network_zone_list.append(ipv4_zone)

            elif test_type in ["BGPv6"]:
                ipv4_zone = NetworkZoneDict(version="v6", subnet_number="1")
                network_zone_list.append(ipv4_zone)

            else:
                ipv4_zone = NetworkZoneDict(version="v4")
                network_zone_list.append(ipv4_zone)
                ipv6_zone = NetworkZoneDict(version="v6")
                network_zone_list.append(ipv6_zone)

        self.network_zone_list = network_zone_list  # list of NetworkZoneDict objects

    def set_network_zone_dict(self, index, network_zone_dict):
        if index < 0 or index >= len(self.network_zone_list):
            msg = "Index out of range"
            logger.error(msg)
            raise IndexError(msg)
        self.network_zone_list[index] = network_zone_dict

    def get_network_zone(self):
        return self.network_zone_list

    def to_dict(self):
        return [network_zone_dict.to_dict() for network_zone_dict in self.network_zone_list]


class NetworkZoneDict:
    def __init__(self, enable: bool = False, version: str = "v4", start: str = "", step: str = "", mask: str = "",
                 sim_router_ip: str = "", count: int = 0, subnet_number: str = ""):
        self.NetworkZoneEnable = "yes" if enable else "no"
        self.SubnetVersion = version
        if version == "v4":
            self.NetworkZoneStart = start or "17.1.0.0"
            self.NetworkZoneStep = step or "0.0.1.0"
            self.NetworkZoneMask = mask or "24"
            # self.SimulatorRouterIPAddr = sim_router_ip or "0.0.1.2#disabled"
            self.SimulatorRouterIPAddr = sim_router_ip or "0.0.1.3"
            self.NetworkZoneCount = count or 1
            self.SubnetNumber = subnet_number or "1"
        else:

            self.NetworkZoneStart = start or "3ffe:0:17:2::0"
            self.NetworkZoneStep = step or "0:0:0:1::0"
            self.NetworkZoneMask = mask or "64"
            self.SimulatorRouterIPAddr = sim_router_ip or "0:0:0:1::1:2#disabled"
            self.NetworkZoneCount = count or 1
            self.SubnetNumber = subnet_number or "2"

    def set_network_zone_enable(self, enable: bool):
        self.NetworkZoneEnable = "yes" if enable else "no"

    def set_subnet_version(self, version: str):
        if version in ("v4", "v6"):
            self.SubnetVersion = version
        else:
            msg = "Subnet Version must be 'v4' or 'v6'"
            logger.error(msg)
            raise ValueError(msg)

    def set_network_range(self, start: str, step: str):
        self.NetworkZoneStart = start
        self.NetworkZoneStep = step

    def set_network_mask(self, mask: str):
        if not mask.isdigit():
            msg = "Network mask must be numeric"
            logger.error(msg)
            raise ValueError(msg)
        self.NetworkZoneMask = mask

    def set_simulator_ip(self, sim_router_ip: str):
        self.SimulatorRouterIPAddr = sim_router_ip

    @staticmethod
    def config_zone_parameters(args, port_config_list):
        """Configure zone parameters

        Args:
            args (tuple): The tuple of the subnet attribute dictionary to be configured
            port_config_list (list): The list of network port objects needs to be modified
        """
        for arg_dict in args:
            for key, val_dict in arg_dict.items():
                port_name = key
                for port_config in port_config_list:
                    if port_config.Interface == port_name:
                        network_zone = port_config.NetworkZone
                        for network_zone_dict in network_zone:
                            if network_zone_dict["SubnetNumber"] == val_dict["SubnetNumber"]:
                                # Modify configuration
                                network_zone_dict.update(val_dict)
                                break

    def to_dict(self):
        return ToolsUtils.to_dict(self)


class BaseCase:
    def set_test_name(self, test_name):
        if not test_name:
            msg = "TestName cannot be empty"
            logger.error(msg)
            raise ValueError(msg)

        if ToolsUtils.check_test_case_name(test_name):
            self.TestName = str(test_name)
            self.DisplayName = str(test_name)

    @staticmethod
    def get_current_time():
        current_time = time.localtime()
        formatted_time = time.strftime("%Y%m%d-%H_%M_%S", current_time)
        return formatted_time

    def __init__(self):
        now_time = self.get_current_time()
        self.TestType = None
        self.TestMode = 'TP'
        self.DUTRole = None
        self.TestName = now_time
        self.DisplayName = now_time
        self.TestDuration = 60
        self.WorkMode = "Standalone"
        self.ImageVersion = "25.06.11"
        self.DutSystemVersion = "Supernova-Cloud 25.06.11 build4407"
        self.ReportInterval = 1
        self.ProxyMode = "Reverse"
        self.IPVersion = "v4"

    # set test type
    def set_test_type(self, test_type):
        self.TestType = test_type

    # set test mode
    def set_test_mode(self, test_mode):
        self.TestMode = test_mode

    # set dut role
    def set_dut_role(self, dut_role):
        self.DUTRole = dut_role

    # set proxy mode
    def set_proxy_mode(self, proxy_mode):
        self.ProxyMode = proxy_mode

    # set test duration
    def set_test_duration(self, test_duration):
        self.TestDuration = test_duration

    # set work mode
    def set_work_mode(self, work_mode):
        self.WorkMode = work_mode

    def to_dict(self):
        if self.TestType.startswith("Rfc") and hasattr(self, "TestDuration"):
            delattr(self, "TestDuration")
        return self.__dict__


class PortStreamTemplate:
    """
    A class of Flow template configuration
    """

    def __init__(self):
        self.StreamTemplate = "ETH_IPV4"

    def to_dict(self):
        return self.__dict__


class BaseLoads:
    def __init__(self, test_type):
        if ToolsUtils.is_dpdk_test_type(test_type):
            # The current user's memory occupancy
            self.UserApplyMemoryMB = 28
            # Memory consumption during use case execution
            self.CaseAssignMemoryGB = 28
            # The proportion of large page memory usage in the test cases execution
            self.DPDKHugeMemoryPct = 40

        loads_callback_dict = {
            "HttpCps": self._handle_http_cps_loads_config,
            "HttpForceCps": self._handle_http_force_cps_loads_config,
            "HttpCc": self._handle_http_cc_loads_config,
            "HttpThroughput": self._handle_http_throughput_loads_config,
            "UdpPps": self._handle_udp_pps_loads_config,
            "TurboTcp": self._handle_turbo_tcp_loads_config,
            "MultiTypeFlood": self._handle_multi_type_flood_loads_config,
            "TcpSessionFlood": self._handle_tcp_session_flood_loads_config,
            "TCPWinnuke": self._handle_tcp_winnuke_loads_config,
            "HttpMultipleRequest": self._handle_http_multiple_request_loads_config,
            "HttpRecursionRequest": self._handle_http_recursion_request_loads_config,
            "Rfc2544Throughput": self._handle_rfc2544_throughput_loads_config,
            "Rfc2544Latency": self._handle_rfc2544_latency_loads_config,
            "Rfc2544LossRate": self._handle_rfc2544_loss_rate_loads_config,
            "Rfc2544BackToBack": self._handle_rfc2544_back_to_back_loads_config,
            "Ipv4FragAttack": self._handle_ipv4_frag_attack_loads_config,
            "ICMPSinglePacketAttack": self._handle_icmp_single_packet_attack_loads_config,
            "IGMPv4SinglePacketAttack": self._handle_igmpv4_single_packet_attack_loads_config,
            "ARPv4SinglePacketAttack": self._handle_arpv4_single_packet_attack_loads_config,
            "TCPSinglePacketAttack": self._handle_tcp_single_packet_attack_loads_config,
            "UDPSinglePacketAttack": self._handle_udp_single_packet_attack_loads_config,
            "UDPPayloadAttack": self._handle_udp_payload_attack_loads_config,
            "SipSinglePacketAttack": self._handle_sip_single_packet_attack_loads_config,
            "DnsServiceAttack": self._handle_dns_service_attack_loads_config,
            "DnsAmplificationAttack": self._handle_dns_amplification_attack_loads_config,
            "SSDPAttack": self._handle_ssdp_attack_loads_config,
            "NtpAmplificationAttack": self._handle_ntp_amplification_attack_loads_config,
            "MemcachedAmplificationAttack": self._handle_memcached_amplification_attack_loads_config,
            "UnknownProtocolSinglePacketAttack": self._handle_unknown_protocol_single_packet_attack_loads_config,
            "HttpRequestFlood": self._handle_http_request_flood_loads_config,
            "HttpsFlood": self._handle_https_flood_loads_config,
            "HTTPSlowRequestFlood": self._handle_httpslow_request_flood_loads_config,
            "HttpConcurrentSlowRead": self._handle_http_concurrent_slow_read_loads_config,
            "HttpConcurrentSlowRequest": self._handle_http_concurrent_slow_request_loads_config,
            "UnicastStorm": self._handle_unicast_storm_loads_config,
            "MulticastStorm": self._handle_multicast_storm_loads_config,
            "BroadcastStorm": self._handle_broadcast_storm_loads_config,
            "SVStormTest": self._handle_sv_storm_test_loads_config,
            "GooseStormTest": self._handle_goose_storm_test_loads_config,
            "MmsConnectStorm": self._handle_mms_connect_storm_loads_config,
            "LLDPStormTest": self._handle_lldp_storm_test_loads_config,
            "VulnerabilityScanner": self._handle_vulnerability_scanner_loads_config,
            "WebScanner": self._handle_web_scanner_loads_config,
            "NetworkDiscovery": self._handle_network_discovery_loads_config,
            "HttpsCps": self._handle_https_cps_loads_config,
            "HttpsCc": self._handle_https_cc_loads_config,
            "HttpsThroughput": self._handle_https_throughput_loads_config,
            "SSLHandshake": self._handle_ssl_handshake_loads_config,
            "AdvancedFuzzing": self._handle_advanced_fuzzing_loads_config,
            "BGPv4": self._handle_bgpv4_loads_config,
            "BGPv6": self._handle_bgpv6_loads_config,
            "ScenarioDescrptionLanguage": self._handle_scenario_description_language_loads_config,
            "WeakPasswordDetection": self._handle_weak_password_detection_loads_config,
        }

        callback = loads_callback_dict.get(test_type)
        if callback:
            callback()
        else:
            pass

    def _handle_http_cps_loads_config(self):
        self.SimUser = 20
        self.HttpRequestTimeoutSecond = 10000
        self.HttpTranscationStatistics = "no"
        self.HttpPercentageLatencyStat = "no"
        self.HttpRequestHashSize = 512
        self.CookieTrafficRatio = 100
        self.SendPktStatEn = "no"
        self.HttpOverLapMode = "user"
        self.HttpThinkTimeMode = "fixed"
        self.MaxThinkTime = 37500
        self.MinThinkTime = 1
        self.ThinkTime = 37500
        self.HttpThinkTimeMaxCc = 4000000
        self.HttpNewSessionTotal = 0
        self.HttpMaxRequest = 0
        self.HttpNewConnReqNum = 0
        self.NewTcpEachRequrest = "no"
        self.HttpPipelineEn = "no"
        self.SimuserFixReq = "no"
        self.HttpRedirectNewTcpEn = "no"
        self.HttpLogTraffic = "no"
        self.OnlyRecordAbnormalResponse = "no"
        self.OnlyRecordAssertFailed = "no"
        self.HttpTrafficLogCount = 1000
        self.HttpWebURLIpStatEn = "no"
        self.HttpWebStatIPNum = 10

    def _handle_http_force_cps_loads_config(self):
        self.OnlyRecordAbnormalResponse = "no"
        self.HttpTranscationStatistics = "no"
        self.HttpThinkTimeMode = "fixed"
        self.ThinkTime = 37500
        self.MinThinkTime = 1
        self.NewTcpEachRequrest = "no"
        self.CookieTrafficRatio = 100
        self.HttpTrafficLogCount = 1000
        self.HttpThinkTimeMaxCc = 1000000
        self.HttpOverLapMode = "none"
        self.HttpRequestTimeoutSecond = 10000
        self.OnlyRecordAssertFailed = "no"
        self.HttpWebStatIPNum = 10
        self.HttpWebURLIpStatEn = "no"
        self.HttpPercentageLatencyStat = "no"
        self.MaxThinkTime = 37500
        self.HttpLogTraffic = "no"
        self.HttpRequestHashSize = 512
        self.HttpCpsSuccessRateTarget = 0

    def _handle_http_cc_loads_config(self):
        self.OnlyRecordAbnormalResponse = "no"
        self.HttpTranscationStatistics = "no"
        self.HttpThinkTimeMode = "fixed"
        self.ThinkTime = 0
        self.MinThinkTime = 1
        self.CookieTrafficRatio = 100
        self.ConcurrentConnection = 6975000
        self.HttpTrafficLogCount = 1000
        self.HttpRequestTimeoutSecond = 10000
        self.OnlyRecordAssertFailed = "no"
        self.SimUser = 256
        self.DelayResponse = "no"
        self.HttpPercentageLatencyStat = "no"
        self.MaxThinkTime = 37500
        self.HttpSendRequestMode = "each"
        self.HttpLogTraffic = "no"
        self.HttpCcOperationPolicy = "no"
        self.ReConnCount = 0
        self.HttpRequestHashSize = 512

    def _handle_http_throughput_loads_config(self):
        self.OnlyRecordAbnormalResponse = "no"
        self.HttpTranscationStatistics = "no"
        self.HttpThinkTimeMode = "fixed"
        self.ThinkTime = 0
        self.MinThinkTime = 1
        self.CookieTrafficRatio = 100
        self.HttpTrafficLogCount = 1000
        self.HttpRequestTimeoutSecond = 10000
        self.OnlyRecordAssertFailed = "no"
        self.SimUser = 256
        self.DelayResponse = "no"
        self.HttpPercentageLatencyStat = "no"
        self.MaxThinkTime = 37500
        self.HttpLogTraffic = "no"
        self.HttpCcOperationPolicy = "no"
        self.ReConnCount = 0
        self.HttpRequestHashSize = 512

    def _handle_udp_pps_loads_config(self):
        self.RecvPacketCount = "16"
        self.SimuserSendPPS = 1
        self.UdpEcho = "disable"
        self.BurstPacketCount = "32"
        self.FragIdAccumulates = "no"
        self.PacketPayloadPolicy = "Fixed"
        self.PolicyChangeCarrier = "Port"
        self.FirstPacketSentDelay = 1
        self.Latency = "disable"
        self.MaxIPFrag = 4
        self.SpecifyPayloadValue = "00"
        self.SimuserSendPacketSecond = 0
        self.SimUser = 256
        self.UDPSendPacketCount = 0
        self.DualFlowMode = "disable"
        self.IPv4FlagsDF = 0
        self.FrameSizePolicy = {
            "SizeChangeMode": "Fixed",
            "FrameSizeFormat": 1518
        }

    def _handle_turbo_tcp_loads_config(self):
        self.SimUser = 256

    def _handle_multi_type_flood_loads_config(self):
        self.SimUser = 256

    def _handle_tcp_session_flood_loads_config(self):
        self.SimUser = 256

    def _handle_tcp_winnuke_loads_config(self):
        self.SimUser = 256

    def _handle_http_multiple_request_loads_config(self):
        self.SimUser = 256

    def _handle_http_recursion_request_loads_config(self):
        self.SimUser = 256

    def _handle_rfc2544_throughput_loads_config(self):
        # The number of UDP streams
        self.SimUser = 256
        # Delay jitter calculation
        self.Latency = "disable"
        # Flow direction; the available values are: enable, disable, both.
        # "enable" indicates two-way; "disable" indicates one-way; "both" means first one-way, then two-way
        self.DualFlowMode = "disable"

        # Load transformation type; the available values are: Fixed, Random, Custom, Stream
        self.PacketPayloadPolicy = "Fixed"
        # When the load transformation type is set to custom load, the load content needs to be configured.
        self.PacketPayloadValue = "0xFF"
        # When the type of load transformation is fixed load, random load or custom load, this item needs to be specified.
        self.FrameSizePolicy = {
            # Frame length transformation mode; the available values are: List, Step, Random, iMix.
            "SizeChangeMode": "List",
            # The format of the List value is: 64, 128; The format of the Step value is: 64-128|+64
            # The format of the Random value is: 128-256
            "FrameSizeFormat": "64,128"
        }
        # Number of retry attempts for testing
        self.MaximumIterativeCycle = 1

        self.CycleDurationPolicy = {
            # Duration adjustment method
            "CycleDurationMode": "Fixed",
            # The unit of test duration; the available values are: TimeSecond, PacketCount
            "CycleDurationUnit": "TimeSecond",
            # When the unit of test duration is seconds of sent traffic, the initial sending time period in seconds needs to be specified.
            "InitialCycleSecond": "60",
            # When the unit of the test duration is the number of sent messages, the initial number of sent messages field needs to be specified.
            "InitialCyclePacket": "10000",
            "MinimumCycleSecond": "0.000064",
            "MinimumCyclePacket": "1",
            "MaximumCycleSecond": "60",
            "MaximumCyclePacket": "10000",
            "SecondResolution": "0.1",
            "PacketResolution": "100",
            "AcceptableLossRate": "0"
        }
        # The duration of aging
        self.AgingTime = 5

        self.SendSpeedPolicy = {
            # Load Iteration Mode ; the available values are: Binary, Step, Mixed, OptStep.
            "SpeedIterateMode": "Binary",
            # Rate Lower Limit (%)
            # When the load iteration mode is selected as binary search or the optimization step size, the value of this item can be modified.
            "LowerSpeedRate": "1",
            # Rate limit (%)
            # When the load iteration mode is selected as step size, binary search or hybrid method , the value of this item can be modified.
            "UpperSpeedRate": "100",
            # Initial rate (%)
            "InitialSpeedRate": "100",
            # Rate step (%)
            # When the load iteration mode is selected as step size or hybrid method, the value of this item can be modified.
            "UpDownStepRate": "10",
            # the search accuracy (%)
            # When the load iteration mode is selected as binary search, hybrid method or optimization step size, the value of this item can be modified.
            "ResolutionRate": "1",
            # Binary search for percentage (%)
            # When the load iteration mode is selected as binary search or hybrid method, the value of this item can be modified.
            "BisectionBackoff": "50",
            # Acceptable packet loss rate
            "AcceptableLossRate": "0"
        }
        self.CorrectLossRateCycle = -1
        # Message sending rate
        self.BurstPacketCount = 32

    def _handle_rfc2544_latency_loads_config(self):
        self.SimUser = 256

        self.Latency = "enable"
        self.DelayType = "LIFO"
        self.DualFlowMode = "enable"

        self.PacketPayloadPolicy = "Fixed"
        self.PacketPayloadValue = "0xFF"

        self.FrameSizePolicy = {
            "SizeChangeMode": "List",
            "FrameSizeFormat": "64,128"
        }

        self.MaximumIterativeCycle = 1

        self.CycleDurationPolicy = {
            "CycleDurationMode": "Fixed",
            "CycleDurationUnit": "TimeSecond",
            "InitialCycleSecond": "10",
            "InitialCyclePacket": "10000",
            "MinimumCycleSecond": "0.000064",
            "MinimumCyclePacket": "1",
            "MaximumCycleSecond": "60",
            "MaximumCyclePacket": "10000",
            "SecondResolution": "0.1",
            "PacketResolution": "100",
            "AcceptableLossRate": "0"
        }

        self.FilterAction = "Drop"
        self.AgingTime = 5

        self.LoadLimitPolicy = {
            "LoadLimitUnit": "percent",
            "LoadLimitMode": "Step",
            "LoadLimitFormat": "10-50|+10"
        }

        self.BurstPacketCount = 32
        self.LoopBackLinkLatency = "no"
        self.DisplayFailWhenLoss = "yes"
        self.AcceptablePacketLossRate = -1

    def _handle_rfc2544_loss_rate_loads_config(self):
        # The number of UDP streams
        self.SimUser = 256

        self.Latency = "disable"
        # Flow direction; the available values are: enable, disable, both.
        # "enable" indicates two-way; "disable" indicates one-way; "both" means first one-way, then two-way
        self.DualFlowMode = "disable"

        # Load transformation type; the available values are: Fixed, Random, Custom, Stream
        self.PacketPayloadPolicy = "Fixed"
        # When the load transformation type is set to custom load, the load content needs to be configured.
        self.PacketPayloadValue = "0xFF"
        # When the type of load transformation is fixed load, random load or custom load, this item needs to be specified.
        self.FrameSizePolicy = {
            # Frame length transformation mode; the available values are: List, Step, Random, iMix.
            "SizeChangeMode": "List",
            # The format of the List value is: 64, 128; The format of the Step value is: 64-128|+64
            # The format of the Random value is: 128-256
            "FrameSizeFormat": "64,128,256,512,1024,1280,1518"
        }

        # Number of retry attempts for testing
        self.MaximumIterativeCycle = 20
        self.CycleDurationPolicy = {
            # Duration adjustment method
            "CycleDurationMode": "Fixed",
            # The unit of test duration; the available values are: TimeSecond, PacketCount
            "CycleDurationUnit": "TimeSecond",
            # When the unit of test duration is seconds of sent traffic, the initial sending time period in seconds needs to be specified.
            "InitialCycleSecond": "60",
            # When the unit of the test duration is the number of sent messages, the initial number of sent messages field needs to be specified.
            "InitialCyclePacket": "10000",
            "MinimumCycleSecond": "0.000064",
            "MinimumCyclePacket": "1",
            "MaximumCycleSecond": "60",
            "MaximumCyclePacket": "10000",
            "SecondResolution": "0.1",
            "PacketResolution": "100",
            "AcceptableLossRate": "0"
        }
        # The duration of aging
        self.AgingTime = 5

        self.LoadLimitPolicy = {
            # Unit of rate load; the available values are: percent, fps, bps, kbps, mbps, Bps
            "LoadLimitUnit": "percent",
            # Rate load mode; the available values are: Step, Random, List, FrameSpeedRate
            "LoadLimitMode": "Step",
            # The format of the Step value is 10-50|+10; The format of the Random value is 10-50
            # The format of the List value is 10,20,50;
            # The format of the FrameSpeedRate value is 10,20,50; At this point, the number of rate lists needs to be equal to that of frame length lists.
            "LoadLimitFormat": "10-50|+10"
        }
        # Message sending rate
        self.BurstPacketCount = 32
        # Packet loss indicates failure.
        self.DisplayFailWhenLoss = "yes"

    def _handle_rfc2544_back_to_back_loads_config(self):
        # The number of UDP streams
        self.SimUser = 256

        self.Latency = "disable"
        # "enable" indicates two-way; "disable" indicates one-way; "both" means first one-way, then two-way
        self.DualFlowMode = "disable"

        # Load transformation type; the available values are: Fixed, Random, Custom, Stream
        self.PacketPayloadPolicy = "Fixed"
        # When the load transformation type is set to custom load, the load content needs to be configured.
        self.PacketPayloadValue = "0xFF"
        # When the type of load transformation is fixed load, random load or custom load, this item needs to be specified.
        self.FrameSizePolicy = {
            # Frame length transformation mode; the available values are: List, Step, Random, iMix.
            "SizeChangeMode": "List",
            # The format of the List value is: 64, 128; The format of the Step value is: 64-128|+64
            # The format of the Random value is: 128-256
            "FrameSizeFormat": "64,128,256,512,1024,1280,1518"
        }

        # Number of retry attempts for testing
        self.MaximumIterativeCycle = 20
        self.CycleDurationPolicy = {
            # Duration adjustment method
            "CycleDurationMode": "Fixed",
            # The unit of test duration; the available values are: TimeSecond, PacketCount
            "CycleDurationUnit": "TimeSecond",
            # When the unit of test duration is seconds of sent traffic, the initial sending time period in seconds needs to be specified.
            "InitialCycleSecond": "60",
            # When the unit of the test duration is the number of sent messages, the initial number of sent messages field needs to be specified.
            "InitialCyclePacket": "10000",
            "MinimumCycleSecond": "0.000064",
            "MinimumCyclePacket": "1",
            "MaximumCycleSecond": "60",
            "MaximumCyclePacket": "10000",
            "SecondResolution": "0.1",
            "PacketResolution": "100",
            "AcceptableLossRate": "0"
        }
        # The duration of aging
        self.AgingTime = 5

        self.LoadLimitPolicy = {
            # Unit of rate load; the available values are: percent, fps, bps, kbps, mbps, Bps
            "LoadLimitUnit": "percent",
            # Rate load mode; the available values are: Step, Random, List, FrameSpeedRate
            "LoadLimitMode": "List",
            # The format of the Step value is 10-50|+10; The format of the Random value is 10-50
            # The format of the List value is 10,20,50;
            # The format of the FrameSpeedRate value is 10,20,50; At this point, the number of rate lists needs to be equal to that of frame length lists.
            "LoadLimitFormat": "100"
        }
        # Message sending rate
        self.BurstPacketCount = 32
        # Packet loss indicates failure.
        self.DisplayFailWhenLoss = "yes"
        self.CorrectLossRateCycle = -1
        self.UpDownGranularity = -1

    def _handle_ipv4_frag_attack_loads_config(self):
        self.DDoSTypeTrafficStat = "no"
        self.MulticastIp = "225.1.1.10"
        self.DDosTypes = {
            "TEARDROP_UDP_FLOOD": 100
        }

    def _handle_icmp_single_packet_attack_loads_config(self):
        self.SimUser = 256
        self.DDosDelayStart = 0
        self.ICMP_REQUEST_FLOOD_FRAME = 68
        self.DDoSTypeTrafficStat = "no"
        self.DDosTypes = {
            "ICMP_REQUEST_FLOOD": 100
        }

    def _handle_igmpv4_single_packet_attack_loads_config(self):
        self.SimUser = 256
        self.MulticastIp = "225.1.1.10"
        self.IGMPV3_RESPONSE_FLOOD_FRAME = 68
        self.DDoSTypeTrafficStat = "no"
        self.DDosTypes = {
            "IGMPV3_RESPONSE_FLOOD": 100
        }

    def _handle_arpv4_single_packet_attack_loads_config(self):
        self.SimUser = 256
        self.DDoSTypeTrafficStat = "no"
        self.DDosTypes = {
            "ARP_REQUEST_FLOOD": 100
        }
        self.ARP_REQUEST_FLOOD_FRAME = 68

    def _handle_tcp_single_packet_attack_loads_config(self):
        self.SimUser = 256
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0
        self.DDosTypes = {
            "SYN_FLOOD": 100
        }
        self.SYN_FLOOD_FRAME = 68

    def _handle_udp_single_packet_attack_loads_config(self):
        self.SimUser = 256
        self.MulticastIp = "225.1.1.10"
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0
        self.DDosTypes = {
            "UDP_FLOOD": 100
        }
        self.UDP_FLOOD_FRAME = 68

    def _handle_udp_payload_attack_loads_config(self):
        self.SimUser = 1
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0

    def _handle_sip_single_packet_attack_loads_config(self):
        self.SimUser = 256
        self.FromName = "sip:+460001111100001"
        self.ToName = "sip:+460001111100002"
        self.ImsHost = "ims.mnc011.mcc460.3gppnetwork.org"
        self.DDoSTypeTrafficStat = "no"
        self.DDosTypes = {
            "SIP_INVITE_FLOOD": 100
        }

    def _handle_dns_service_attack_loads_config(self):
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0
        self.SimUser = 256

    def _handle_dns_amplification_attack_loads_config(self):
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0
        self.DNSQueryTimeOut = 1000

    def _handle_ssdp_attack_loads_config(self):
        self.SimUser = 256
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0
        self.AttackStute = "Multi"
        self.SsdpMulticastStormIp = "239.255.255.250"
        self.SsdpMulticastStormIpIpv6 = "FF02::C"
        self.SsdpMultiPort = "1900"
        self.DNSQueryTimeOut = 1000
        self.SSDPAmpDDos = "no"

    def _handle_ntp_amplification_attack_loads_config(self):
        self.SimUser = 256
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0
        self.NTPMonlistTimeout = "500"
        self.NTPAmpDDos = "no"

    def _handle_memcached_amplification_attack_loads_config(self):
        self.SimUser = 256
        self.DDoSTypeTrafficStat = "no"
        self.DDosDelayStart = 0
        self.IPv4AttackDstIpAddr = "17.1.2.2"
        self.IPv6AttackDstIpAddr = "3ffe:0:17:2::1:3"
        self.MemcachedCacheSize = 9000
        self.MemAmpDDos = "no"

    def _handle_unknown_protocol_single_packet_attack_loads_config(self):
        self.SimUser = 256
        self.DDoSTypeTrafficStat = "no"
        self.UNKNOWN_PROTOCOL_ATTACK = 100
        self.UNKNOWN_PROTOCOL_ATTACK_FRAME = 1500
        self.DDosTypes = {
            "UNKNOWN_PROTOCOL_ATTACK": 100
        }

    def _handle_http_request_flood_loads_config(self):
        self.SimUser = 256
        self.HTTPAttackRecord = 0
        self.DDosDelayStart = 0
        self.HttpTranscationStatistics = "no"
        self.DDosModel = "no"
        self.HttpRequestTimeoutSecond = 5000
        self.HttpRequestHashSize = 512
        self.HttpMaxRequest = 0

    def _handle_https_flood_loads_config(self):
        self.DDosDelayStart = 0
        self.SimUser = 256

    def _handle_httpslow_request_flood_loads_config(self):
        self.SimUser = 256
        self.DDosDelayStart = 0
        self.HTTPUnusualHeader = "yes"
        self.SlowReqContentLength = "0"
        self.HttpRequestTimeoutSecond = 10000
        self.RequestFloodSendCount = 1
        self.SegmentSendIntervalUsecond = 0
        self.HttpRequestHashSize = 512

    def _handle_http_concurrent_slow_read_loads_config(self):
        self.SimUser = 256
        self.HttpRequestTimeoutSecond = 5000
        self.ConcurrentConnection = 8000000

    def _handle_http_concurrent_slow_request_loads_config(self):
        self.SimUser = 256
        self.HttpRequestTimeoutSecond = 5000
        self.ConcurrentConnection = 8000000
        self.ReConnCount = 60

    def _handle_unicast_storm_loads_config(self):
        self.SimUser = 256
        self.FrameSizePolicy = {
            "SizeChangeMode": "Fixed",
            "FrameSizeFormat": 64
        }
        self.PingEnable = "no"
        self.PingInterval = 5

    def _handle_multicast_storm_loads_config(self):
        self.SimUser = 256
        self.FrameSizePolicy = {
            "SizeChangeMode": "Fixed",
            "FrameSizeFormat": 64
        }
        self.PingEnable = "no"
        self.PingInterval = 5

    def _handle_broadcast_storm_loads_config(self):
        self.SimUser = 256
        self.PingEnable = "no"
        self.PingInterval = 5

    def _handle_sv_storm_test_loads_config(self):
        self.ChangeMacAddrEnable = "no"
        self.SvAPPIDChangeEn = "no"
        self.SvIDChangeEn = "no"
        self.FrameSizePolicy = {
            "SizeChangeMode": "Fixed",
            "FrameSizeFormat": 79
        }
        self.Latency = "enable"
        self.PingEnable = "no"
        self.PingInterval = 5
        self.GooseDstMacMix = "01:0C:CD:04:00:01"
        self.GooseDstMacMax = "01:0C:CD:04:01:FF"
        self.AppIDMix = "0x4000"
        self.AppIDMax = "0xFFFF"
        self.SimUser = 256

    def _handle_goose_storm_test_loads_config(self):
        self.ChangeMacAddrEnable = "no"
        self.ChangeStEnable = "no"
        self.ChangeSqEnable = "no"
        self.PingEnable = "no"
        self.PingInterval = 5
        self.DstMacRangeMix = "01:0C:CD:04:00:01"
        self.DstMacRangeMax = "01:0C:CD:04:01:FF"
        self.SqRangeMix = "0"
        self.SqRangeMax = "65535"
        self.StEnableMix = "0"
        self.StEnableMax = "65535"
        self.SimUser = 256

    def _handle_mms_connect_storm_loads_config(self):
        self.SimUser = 32
        self.PayloadStreamLoopCount = 0
        self.GproRequestTimeoutSecond = 5
        self.PingEnable = "no"
        self.PingInterval = 5

    def _handle_lldp_storm_test_loads_config(self):
        self.LLDPTestType = "0"
        self.PingEnable = "no"
        self.PingInterval = 5
        self.SimUser = 256

    def _handle_vulnerability_scanner_loads_config(self):
        self.Scan = "Full and fast"
        self.Qod = 70
        self.Remark = ""

    def _handle_web_scanner_loads_config(self):
        self.TestPauseSecond = 0
        self.ScanTuningOptions = "0123456789abcdef"
        self.EncodingEvasion = ""
        self.SslForceMode = "no"
        self.BackgroundStream = "no"

    def _handle_network_discovery_loads_config(self):
        self.ScanConfig = "Intense scan"
        self.ScriptConfiguration = {}
        self.TestSpeed = "-T4"
        self.MinRate = "auto"
        self.FixedValue = 10000

    def _handle_https_cps_loads_config(self):
        self.SimUser = 20
        self.HttpRequestTimeoutSecond = 100000
        self.HttpTranscationStatistics = "no"
        self.HttpPercentageLatencyStat = "no"
        self.HttpRequestHashSize = 512
        self.CookieTrafficRatio = 100
        self.CoreRunMode = "mt"
        self.HttpRedirectNewTcpEn = "no"
        self.HttpOverLapMode = "none"
        self.HttpThinkTimeMode = "fixed"
        self.MaxThinkTime = 37500
        self.MinThinkTime = 1
        self.ThinkTime = 37500
        self.HttpThinkTimeMaxCc = 100000
        self.HttpNewSessionTotal = 0
        self.HttpMaxRequest = 0
        self.HttpNewConnReqNum = 0
        self.NewTcpEachRequrest = "no"
        self.HttpLogTraffic = "no"
        self.OnlyRecordAbnormalResponse = "no"
        self.OnlyRecordAssertFailed = "no"
        self.HttpTrafficLogCount = 1000
        self.HttpWebURLIpStatEn = "no"
        self.HttpWebStatIPNum = 10
        self.ExtendedMasterSecret = "no"
        self.SSLExtServerName = ""
        self.SSLEMSen = "yes"
        self.SSLMtE = "yes"
        self.CertificateRevocationList = "no"
        self.CRLFilePath = ""
        self.SSLCommonNameCheck = "no"
        self.SSLVerifyCNHostName = ""
        self.SSLDebugLevel = 0
        self.FisecCardLogLevel = 3
        self.FisecCardSM2Engine = 1
        self.FisecCardSM3Engine = 1
        self.FisecCardSM4Engine = 1
        self.FisecCardRandomEngine = 1

    def _handle_https_cc_loads_config(self):
        self.SimUser = 32
        self.HttpRequestTimeoutSecond = 100000
        self.HttpTranscationStatistics = "no"
        self.HttpPercentageLatencyStat = "no"
        self.HttpRequestHashSize = 512
        self.CookieTrafficRatio = 100
        self.DutSslOffload = "disable"
        self.ConcurrentConnection = 200000
        self.DelayResponse = "no"
        self.HttpThinkTimeMode = "fixed"
        self.MaxThinkTime = 37500
        self.MinThinkTime = 1
        self.ThinkTime = 0
        self.HttpSendRequestMode = "each"
        self.ReConnCount = 0
        self.HttpCcOperationPolicy = "no"
        self.HttpLogTraffic = "no"
        self.OnlyRecordAbnormalResponse = "no"
        self.OnlyRecordAssertFailed = "no"
        self.HttpTrafficLogCount = 1000
        self.ExtendedMasterSecret = "no"
        self.SSLExtServerName = ""
        self.SSLEMSen = "yes"
        self.SSLMtE = "yes"
        self.CertificateRevocationList = "no"
        self.CRLFilePath = ""
        self.SSLCommonNameCheck = "no"
        self.SSLVerifyCNHostName = ""
        self.SSLDebugLevel = 0
        self.FisecCardLogLevel = 3
        self.FisecCardSM2Engine = 1
        self.FisecCardSM3Engine = 1
        self.FisecCardSM4Engine = 1
        self.FisecCardRandomEngine = 1
        self.HttpRedirectNewTcpEn = "no"

    def _handle_https_throughput_loads_config(self):
        self.SimUser = 20
        self.HttpRequestTimeoutSecond = 100000
        self.HttpTranscationStatistics = "no"
        self.HttpPercentageLatencyStat = "no"
        self.HttpRequestHashSize = 512
        self.CookieTrafficRatio = 100
        self.DelayResponse = "no"
        self.HttpThinkTimeMode = "fixed"
        self.MaxThinkTime = 37500
        self.MinThinkTime = 1
        self.ThinkTime = 0
        self.ReConnCount = 0
        self.HttpCcOperationPolicy = "no"
        self.HttpLogTraffic = "no"
        self.OnlyRecordAbnormalResponse = "no"
        self.OnlyRecordAssertFailed = "no"
        self.HttpTrafficLogCount = 1000
        self.ExtendedMasterSecret = "no"
        self.SSLExtServerName = ""
        self.SSLEMSen = "yes"
        self.SSLMtE = "yes"
        self.CertificateRevocationList = "no"
        self.CRLFilePath = ""
        self.SSLCommonNameCheck = "no"
        self.SSLVerifyCNHostName = ""
        self.SSLDebugLevel = 0
        self.FisecCardLogLevel = 3
        self.FisecCardSM2Engine = 1
        self.FisecCardSM3Engine = 1
        self.FisecCardSM4Engine = 1
        self.FisecCardRandomEngine = 1
        self.HttpRedirectNewTcpEn = "no"

    def _handle_ssl_handshake_loads_config(self):
        self.SimUser = 20
        self.HttpTranscationStatistics = "no"
        self.HttpPercentageLatencyStat = "no"
        self.HttpRequestHashSize = 512
        self.CookieTrafficRatio = 100
        self.CoreRunMode = "mt"
        self.HttpNewSessionTotal = 0
        self.ExtendedMasterSecret = "no"
        self.SSLExtServerName = ""
        self.SSLEMSen = "yes"
        self.SSLMtE = "yes"
        self.CertificateRevocationList = "no"
        self.CRLFilePath = ""
        self.SSLCommonNameCheck = "no"
        self.SSLVerifyCNHostName = ""
        self.SSLDebugLevel = 0
        self.FisecCardLogLevel = 3
        self.FisecCardSM2Engine = 1
        self.FisecCardSM3Engine = 1
        self.FisecCardSM4Engine = 1
        self.FisecCardRandomEngine = 1
        self.HttpRedirectNewTcpEn = "no"

    def _handle_advanced_fuzzing_loads_config(self):
        self.SleepTime = 0
        self.RestartThreshold = 3
        self.RestartSleepTime = 2
        self.IndexStart = 1
        self.IndexEnd = 30000
        self.FuzzDbKeepOnlyNPassCases = 10
        self.ReuseTargetConnection = "no"
        self.Checksum = "no"
        self.ChecksumValue = "0x3a"
        self.CheckDataReceivedEachRequest = "no"
        self.ReceiveDataAfterFuzz = "no"

    def _handle_bgpv4_loads_config(self):
        self.SimUser = 256
        self.PolicyChangeCarrier = "Port"
        self.PacketPayloadPolicy = "Fixed"
        self.FrameSizePolicy = {
            "SizeChangeMode": "Fixed",
            "FrameSizeFormat": 64
        }
        self.PacketMaxCount = "10000"
        self.BurstPacketCount = "1"

    def _handle_bgpv6_loads_config(self):
        self.SimUser = 256
        self.PolicyChangeCarrier = "Port"
        self.PacketPayloadPolicy = "Fixed"
        self.FrameSizePolicy = {
            "SizeChangeMode": "Fixed",
            "FrameSizeFormat": 80
        }
        self.PacketMaxCount = "10000"
        self.BurstPacketCount = "1"

    def _handle_scenario_description_language_loads_config(self):
        self.SendWaitTime = 0
        self.SendNumCyles = 1
        self.ScenarioTimeout = 20
        self.ScenarioInterval = 1
        self.SockRecvTimeout = 15

    def _handle_weak_password_detection_loads_config(self):
        self.WeakAgreementType = "ftp"
        self.SpecifiedUserEnable = "no"
        self.SpecifiedUser = "admin"
        self.SpecifiedPasswordEnable = "no"
        self.SpecifiedPassword = "admin"
        self.EmptyPasswordEnable = "no"
        self.UsernameEntityEnable = "no"
        self.UsernameReverseEnable = "no"
        self.UserDictionary = "无"
        self.PasswordDictionary = "无"
        self.SingleThreadCount = 16
        self.GlobalThreadCount = 64
        self.RequestTimedOut = 32
        self.SslConnectEnable = "no"

    def set_send_wait_time(self, value):
        self.SendWaitTime = value

    def set_send_num_cyles(self, value):
        self.SendNumCyles = value

    def set_scenario_timeout(self, value):
        self.ScenarioTimeout = value

    def set_scenario_interval(self, value):
        self.ScenarioInterval = value

    def set_sock_recv_timeout(self, value):
        self.SockRecvTimeout = value

    def set_sim_user(self, value):
        self.SimUser = value

    def set_policy_change_carrier(self, value):
        self.PolicyChangeCarrier = value

    def set_packet_payload_policy(self, value):
        self.PacketPayloadPolicy = value

    def set_frame_size_policy(self, value):
        self.FrameSizePolicy = value

    def set_packet_max_count(self, value):
        self.PacketMaxCount = value

    def set_burst_packet_count(self, value):
        self.BurstPacketCount = value

    def set_sleep_time(self, value):
        self.SleepTime = value

    def set_restart_threshold(self, value):
        self.RestartThreshold = value

    def set_restart_sleep_time(self, value):
        self.RestartSleepTime = value

    def set_index_start(self, value):
        self.IndexStart = value

    def set_index_end(self, value):
        self.IndexEnd = value

    def set_fuzz_db_keep_only_n_pass_cases(self, value):
        self.FuzzDbKeepOnlyNPassCases = value

    def set_reuse_target_connection(self, value):
        self.ReuseTargetConnection = value

    def set_checksum(self, value):
        self.Checksum = value

    def set_checksum_value(self, value):
        self.ChecksumValue = value

    def set_check_data_received_each_request(self, value):
        self.CheckDataReceivedEachRequest = value

    def set_receive_data_after_fuzz(self, value):
        self.ReceiveDataAfterFuzz = value

    def set_http_transcation_statistics(self, value):
        self.HttpTranscationStatistics = value

    def set_http_percentage_latency_stat(self, value):
        self.HttpPercentageLatencyStat = value

    def set_http_request_hash_size(self, value):
        self.HttpRequestHashSize = value

    def set_cookie_traffic_ratio(self, value):
        self.CookieTrafficRatio = value

    def set_core_run_mode(self, value):
        self.CoreRunMode = value

    def set_http_new_session_total(self, value):
        self.HttpNewSessionTotal = value

    def set_extended_master_secret(self, value):
        self.ExtendedMasterSecret = value

    def set_ssl_ext_server_name(self, value):
        self.SSLExtServerName = value

    def set_ssl_ems_en(self, value):
        self.SSLEMSen = value

    def set_ssl_mte(self, value):
        self.SSLMtE = value

    def set_certificate_revocation_list(self, value):
        self.CertificateRevocationList = value

    def set_crl_file_path(self, value):
        self.CRLFilePath = value

    def set_ssl_common_name_check(self, value):
        self.SSLCommonNameCheck = value

    def set_ssl_verify_cn_host_name(self, value):
        self.SSLVerifyCNHostName = value

    def set_ssl_debug_level(self, value):
        self.SSLDebugLevel = value

    def set_fisec_card_log_level(self, value):
        self.FisecCardLogLevel = value

    def set_fisec_card_sm2_engine(self, value):
        self.FisecCardSM2Engine = value

    def set_fisec_card_sm3_engine(self, value):
        self.FisecCardSM3Engine = value

    def set_fisec_card_sm4_engine(self, value):
        self.FisecCardSM4Engine = value

    def set_fisec_card_random_engine(self, value):
        self.FisecCardRandomEngine = value

    def set_http_redirect_new_tcp_en(self, value):
        self.HttpRedirectNewTcpEn = value

    def set_http_request_timeout_second(self, value):
        self.HttpRequestTimeoutSecond = value

    def set_delay_response(self, value):
        self.DelayResponse = value

    def set_http_think_time_mode(self, value):
        self.HttpThinkTimeMode = value

    def set_max_think_time(self, value):
        self.MaxThinkTime = value

    def set_min_think_time(self, value):
        self.MinThinkTime = value

    def set_think_time(self, value):
        self.ThinkTime = value

    def set_re_conn_count(self, value):
        self.ReConnCount = value

    def set_http_cc_operation_policy(self, value):
        self.HttpCcOperationPolicy = value

    def set_http_log_traffic(self, value):
        self.HttpLogTraffic = value

    def set_only_record_abnormal_response(self, value):
        self.OnlyRecordAbnormalResponse = value

    def set_only_record_assert_failed(self, value):
        self.OnlyRecordAssertFailed = value

    def set_http_traffic_log_count(self, value):
        self.HttpTrafficLogCount = value

    def set_dut_ssl_offload(self, value):
        self.DutSslOffload = value

    def set_concurrent_connection(self, value):
        self.ConcurrentConnection = value

    def set_http_send_request_mode(self, value):
        self.HttpSendRequestMode = value

    def set_ssl_em_sen(self, value):
        self.SSLEMSen = value

    def set_http_over_lap_mode(self, value):
        self.HttpOverLapMode = value

    def set_http_think_time_max_cc(self, value):
        self.HttpThinkTimeMaxCc = value

    def set_http_max_request(self, value):
        self.HttpMaxRequest = value

    def set_http_new_conn_req_num(self, value):
        self.HttpNewConnReqNum = value

    def set_new_tcp_each_requrest(self, value):
        self.NewTcpEachRequrest = value

    def set_http_web_url_ip_stat_en(self, value):
        self.HttpWebURLIpStatEn = value

    def set_http_web_stat_ip_num(self, value):
        self.HttpWebStatIPNum = value

    def set_ssl_mt_e(self, value):
        self.SSLMtE = value

    def set_scan_config(self, value):
        self.ScanConfig = value

    def set_script_configuration(self, value):
        self.ScriptConfiguration = value

    def set_test_speed(self, value):
        self.TestSpeed = value

    def set_min_rate(self, value):
        self.MinRate = value

    def set_fixed_value(self, value):
        self.FixedValue = value

    def set_test_pause_second(self, value):
        self.TestPauseSecond = value

    def set_scan_tuning_options(self, value):
        self.ScanTuningOptions = value

    def set_encoding_evasion(self, value):
        self.EncodingEvasion = value

    def set_ssl_force_mode(self, value):
        self.SslForceMode = value

    def set_background_stream(self, value):
        self.BackgroundStream = value

    def set_scan(self, value):
        self.Scan = value

    def set_qod(self, value):
        self.Qod = value

    def set_remark(self, value):
        self.Remark = value

    def set_lldp_test_type(self, value):
        self.LLDPTestType = value

    def set_ping_enable(self, value):
        self.PingEnable = value

    def set_ping_interval(self, value):
        self.PingInterval = value

    def set_payload_stream_loop_count(self, value):
        self.PayloadStreamLoopCount = value

    def set_gpro_request_timeout_second(self, value):
        self.GproRequestTimeoutSecond = value

    def set_change_mac_addr_enable(self, value):
        self.ChangeMacAddrEnable = value

    def set_change_st_enable(self, value):
        self.ChangeStEnable = value

    def set_change_sq_enable(self, value):
        self.ChangeSqEnable = value

    def set_dst_mac_range_mix(self, value):
        self.DstMacRangeMix = value

    def set_dst_mac_range_max(self, value):
        self.DstMacRangeMax = value

    def set_sq_range_mix(self, value):
        self.SqRangeMix = value

    def set_sq_range_max(self, value):
        self.SqRangeMax = value

    def set_st_enable_mix(self, value):
        self.StEnableMix = value

    def set_st_enable_max(self, value):
        self.StEnableMax = value

    def set_sv_appid_change_en(self, value):
        self.SvAPPIDChangeEn = value

    def set_sv_id_change_en(self, value):
        self.SvIDChangeEn = value

    def set_latency(self, value):
        self.Latency = value

    def set_goose_dst_mac_mix(self, value):
        self.GooseDstMacMix = value

    def set_goose_dst_mac_max(self, value):
        self.GooseDstMacMax = value

    def set_app_id_mix(self, value):
        self.AppIDMix = value

    def set_app_id_max(self, value):
        self.AppIDMax = value

    def set_ddos_delay_start(self, value):
        self.DDosDelayStart = value

    def set_http_unusual_header(self, value):
        self.HTTPUnusualHeader = value

    def set_slow_req_content_length(self, value):
        self.SlowReqContentLength = value

    def set_request_flood_send_count(self, value):
        self.RequestFloodSendCount = value

    def set_segment_send_interval_usecond(self, value):
        self.SegmentSendIntervalUsecond = value

    def set_http_attack_record(self, value):
        self.HTTPAttackRecord = value

    def set_ddos_model(self, value):
        self.DDosModel = value

    def set_ddos_type_traffic_stat(self, value):
        self.DDoSTypeTrafficStat = value

    def set_ddos_types(self, value):
        self.DDosTypes = value

    def set_unknown_protocol_attack_frame(self, value):
        self.UNKNOWN_PROTOCOL_ATTACK_FRAME = value

    def set_ipv4_attack_dst_ip_addr(self, value):
        self.IPv4AttackDstIpAddr = value

    def set_ipv6_attack_dst_ip_addr(self, value):
        self.IPv6AttackDstIpAddr = value

    def set_memcached_cache_size(self, value):
        self.MemcachedCacheSize = value

    def set_mem_amp_ddos(self, value):
        self.MemAmpDDos = value

    def set_ntp_amp_ddos(self, value: str):
        """
        Set the NTP amplification DDoS flag.

        Args:
            value (str): "yes" to enable, "no" to disable.

        Raises:
            ValueError: If input is not "yes" or "no".
        """
        if value not in ("yes", "no"):
            raise ValueError("Value must be 'yes' or 'no'")
        self.NTPAmpDDos = value

    def set_ntp_monlist_timeout(self, value):
        """
        Set the NTP monlist timeout.

        Args:
            value (int): The timeout value.
        """
        self.NTPMonlistTimeout = value

    def set_attack_stute(self, value: str):
        """
        Set DDoS type traffic statistics flag

        Args:
            value (str): "yes" to enable statistics, "no" to disable

        Raises:
            ValueError: If input is not "yes" or "no"
        """
        if value not in ("Multi", "Single"):
            raise ValueError("Value must be 'Multi' or 'Single'")
        self.AttackStute = value

    def set_ssdp_multicast_storm_ip(self, value: str):
        """
        Set the SSDP multicast storm IP address.

        Args:
            value (str): The IP address.
        """
        self.SsdpMulticastStormIp = value

    def set_ssdp_multicast_storm_ip_ipv6(self, value: str):
        """
        Set the SSDP multicast storm IP address (IPv6).

        Args:
            value (str): The IP address.
        """
        self.SsdpMulticastStormIpIpv6 = value

    def set_ssdp_multi_port(self, value: str):
        """
        Set the SSDP multicast storm port.

        Args:
            value (str): The port number.
        """
        self.SsdpMultiPort = value

    def set_dns_query_timeout(self, value):
        """
        Set the DNS query timeout.

        Args:
            value (int): The timeout value.
        """
        self.DNSQueryTimeOut = value

    def set_ssdp_amp_ddos(self, value: str):
        """
        Set the SSDP amplification DDoS flag.

        Args:
            value (str): "yes" to enable, "no" to disable.

        Raises:
            ValueError: If input is not "yes" or "no".
        """
        if value not in ("yes", "no"):
            raise ValueError("Value must be 'yes' or 'no'")
        self.SSDPAmpDDos = value

    def set_from_name(self, value):
        """
        Set the FromName value.

        Args:
            value (str): The FromName value.
        """
        self.FromName = value

    def set_to_name(self, value):
        """
        Set the ToName value.

        Args:
            value (str): The ToName value.
        """
        self.ToName = value

    def set_ims_host(self, value):
        """
        Set the ImsHost value.

        Args:
            value (str): The ImsHost value.
        """
        self.ImsHost = value

    def set_multicast_ip(self, ip: str):
        """
        Set multicast IP address

        Args:
            ip (str): Valid IPv4 multicast address (

            ip (str): Valid IPv4 multicast address (IP_ADDRESS - IP_ADDRESS): Valid IPv4 multicast address (IP_ADDRESS - 239.255.255.255)
        Raises:
            ValueError: If invalid multicast IP format
        """
        import ipaddress
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            if not ip_obj.is_multicast:
                raise ValueError
            self.MulticastIp = str(ip_obj)
        except (ipaddress.AddressValueError, ValueError):
            raise ValueError(f"Invalid multicast IP: {ip}")

    def set_udp_flood_frame(self, value):
        """
        Set the udp flood frame size.

        Args:
            value (int): The frame size.
        """
        self.UDP_FLOOD_FRAME = value

    def set_syn_flood_frame(self, value):
        """
        Set the syn flood frame size.

        Args:
            value (int): The frame size.
        """
        self.SYN_FLOOD_FRAME = value

    def set_arp_request_flood_frame(self, value):
        """
        Set the arp request flood frame size.

        Args:
            value (int): The frame size.
        """
        self.ARP_REQUEST_FLOOD_FRAME = value

    def set_igmp_response_flood_frame(self, value):
        """
        Set the IGMPv3 response flood frame size.

        Args:
            value (int): The frame size.
        """
        self.IGMPV3_RESPONSE_FLOOD_FRAME = value

    def set_icmp_request_flood_frame(self, value):
        """
        Set the ICMP request flood frame size.

        Args:
            value (int): The frame size.
        """
        self.ICMP_REQUEST_FLOOD_FRAME = value

    def set_dual_flow_mode(self, value):
        """
        Set whether dual - flow mode is enabled.

        Args:
            value (str): "enable" or "disable".
        """
        self.DualFlowMode = value

    def set_cycle_duration_policy(self, value):
        self.CycleDurationPolicy.update(value)

    def set_delay_type(self, val):
        self.DelayType = val

    def set_packet_payload_value(self, val):
        self.PacketPayloadValue = val

    def set_maximum_iterative_cycle(self, val):
        self.MaximumIterativeCycle = val

    def set_filter_action(self, val):
        self.FilterAction = val

    def set_aging_time(self, val):
        self.AgingTime = val

    def set_load_limit_policy(self, val):
        self.LoadLimitPolicy = val

    def set_loopback_latency(self, val):
        self.LoopBackLinkLatency = val

    def set_display_fail_when_loss(self, val):
        self.DisplayFailWhenLoss = val

    def set_acceptable_packet_loss_rate(self, val):
        self.AcceptablePacketLossRate = val

    def set_recv_packet_count(self, value):
        """
        Set the received packet count.

        Args:
            value (str): The received packet count.
        """
        self.RecvPacketCount = value

    def set_simuser_send_pps(self, value):
        """
        Set the packets per second sent by simulated users.

        Args:
            value (int): The packets per second value.
        """
        self.SimuserSendPPS = value

    def set_udp_echo(self, value):
        """
        Set whether UDP echo is enabled.

        Args:
            value (str): "enable" or "disable".
        """
        self.UdpEcho = value

    def set_frag_id_accumulates(self, value):
        """
        Set whether the fragment ID accumulates.

        Args:
            value (str): "yes" or "no".
        """
        self.FragIdAccumulates = value

    def set_first_packet_sent_delay(self, value):
        """
        Set the delay for sending the first packet.

        Args:
            value (int): The delay value.
        """
        self.FirstPacketSentDelay = value

    def set_max_ip_frag(self, value):
        """
        Set the maximum number of IP fragments.

        Args:
            value (int): The maximum number of IP fragments.
        """
        self.MaxIPFrag = value

    def set_specify_payload_value(self, value):
        """
        Set the specified payload value.

        Args:
            value (str): The specified payload value, e.g., "00".
        """
        self.SpecifyPayloadValue = value

    def set_simuser_send_packet_second(self, value):
        """
        Set the number of packets sent by simulated users per second.

        Args:
            value (int): The number of packets.
        """
        self.SimuserSendPacketSecond = value

    def set_udp_send_packet_count(self, value):
        """
        Set the number of UDP packets sent.

        Args:
            value (int): The number of UDP packets.
        """
        self.UDPSendPacketCount = value

    def set_ipv4_flags_df(self, value):
        """
        Set the IPv4 Flags DF value.

        Args:
            value (int): The IPv4 Flags DF value.
        """
        self.IPv4FlagsDF = value

    def set_http_cps_success_rate_target(self, value):
        self.HttpCpsSuccessRateTarget = value

    def set_send_pkt_stat_en(self, value):
        self.SendPktStatEn = value

    def set_http_pipeline_en(self, value):
        self.HttpPipelineEn = value

    def set_simuser_fix_req(self, value):
        self.SimuserFixReq = value

    def set_user_apply_memory_mb(self, value):
        self.UserApplyMemoryMB = value

    def set_case_assign_memory_gb(self, value):
        self.CaseAssignMemoryGB = value

    def set_dpdk_huge_memory_pct(self, value):
        self.DPDKHugeMemoryPct = value

    def to_dict(self):
        return self.__dict__


class BaseCaseObject:
    def __init__(self, test_type):
        case_object_callback_dict = {
            "HttpCps": self._handle_http_cps_case_object_config,
            "HttpForceCps": self._handle_http_force_cps_case_object_config,
            "HttpCc": self._handle_http_cc_case_object_config,
            "HttpThroughput": self._handle_http_throughput_case_object_config,
            "UdpPps": self._handle_udp_pps_case_object_config,
            "HttpRequestFlood": self._handle_http_request_flood_case_object_config,
            "HttpMultipleRequest": self._handle_http_multiple_request_case_object_config,
            "HttpRecursionRequest": self._handle_http_recursion_request_case_object_config,
            "HttpConcurrentSlowRead": self._handle_http_concurrent_slow_read_case_object_config,
            "HttpConcurrentSlowRequest": self._handle_http_concurrent_slow_request_case_object_config,
            "Rfc2544Throughput": self._handle_rfc2544_throughput_case_object_config,
            "Rfc2544Latency": self._handle_rfc2544_latency_case_object_config,
            "Rfc2544LossRate": self._handle_rfc2544_loss_rate_case_object_config,
            "Rfc2544BackToBack": self._handle_rfc2544_back_to_back_case_object_config,
            "UDPPayloadAttack": self._handle_udp_payload_attack_case_object_config,
            "DnsServiceAttack": self._handle_dns_service_attack_case_object_config,
            "DnsAmplificationAttack": self._handle_dns_amplification_attack_case_object_config,
            "HttpsFlood": self._handle_https_flood_case_object_config,
            "TcpSessionFlood": self._handle_tcp_session_flood_case_object_config,
            "HTTPSlowRequestFlood": self._handle_httpslow_request_flood_case_object_config,
            "MmsConnectStorm": self._handle_mms_connect_storm_case_object_config,
            "VulnerabilityScanner": self._handle_vulnerability_scanner_case_object_config,
            "HttpsCps": self._handle_https_cps_case_object_config,
            "HttpsCc": self._handle_https_cc_case_object_config,
            "HttpsThroughput": self._handle_https_throughput_case_object_config,
            "SSLHandshake": self._handle_ssl_handshake_case_object_config,
            "AdvancedFuzzing": self._handle_advanced_fuzzing_case_object_config,
            "ScenarioDescrptionLanguage": self._handle_scenario_descrption_language_case_object_config,
            "WebScanner": self._handle_web_scanner_case_object_config
        }

        callback = case_object_callback_dict.get(test_type)
        if callback:
            callback()
        else:
            # case object is null
            pass

    def _handle_http_cps_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认156字节网页请求"

    def _handle_http_force_cps_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认156字节网页请求"

    def _handle_http_cc_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认156字节网页请求"

    def _handle_http_throughput_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认512K字节网页请求"

    def _handle_udp_pps_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认156字节网页请求"

    def _handle_http_request_flood_case_object_config(self):
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认根网页请求"

    def _handle_http_multiple_request_case_object_config(self):
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认根网页请求"

    def _handle_http_recursion_request_case_object_config(self):
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认根网页请求"

    def _handle_http_concurrent_slow_read_case_object_config(self):
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认根网页请求"

    def _handle_http_concurrent_slow_request_case_object_config(self):
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认根网页请求"

    def _handle_rfc2544_throughput_case_object_config(self):
        # Monitoring of the tested equipment
        self.Monitor = "默认监控器对象Ping"
        # iMIX mixed frame length
        self.iMixName = "默认混合流量"

    def _handle_rfc2544_latency_case_object_config(self):
        # Monitoring of the tested equipment
        self.Monitor = "默认监控器对象Ping"
        # iMIX mixed frame length
        self.iMixName = "默认混合流量"

    def _handle_rfc2544_loss_rate_case_object_config(self):
        # Monitoring of the tested equipment
        self.Monitor = "默认监控器对象Ping"
        # iMIX mixed frame length
        self.iMixName = "默认混合流量"

    def _handle_rfc2544_back_to_back_case_object_config(self):
        # Monitoring of the tested equipment
        self.Monitor = "默认监控器对象Ping"
        # iMIX mixed frame length
        self.iMixName = "默认混合流量"

    def _handle_udp_payload_attack_case_object_config(self):
        self.PacketPayloadOBJ = "默认handle_over_udp载荷模板"

    def _handle_dns_service_attack_case_object_config(self):
        self.Dns = "默认DNS服务攻击"
        self.Dnskey = "默认RSASHA256套件"

    def _handle_dns_amplification_attack_case_object_config(self):
        self.Dns = "默认DNS放大攻击"
        self.Dnskey = "默认RSASHA256套件"

    def _handle_https_flood_case_object_config(self):
        self.SSLServerCertConfig = "默认RSA算法1024位私钥带密码证书套件"

    def _handle_tcp_session_flood_case_object_config(self):
        self.PacketPayloadOBJ = "默认handle_over_tcp载荷模板"

    def _handle_httpslow_request_flood_case_object_config(self):
        self.Variate = "默认攻击Payload变量列表"
        self.WebTestProjectName = "默认Web攻击测试项目"
        self.FileObject = "默认SlowGet网页请求"

    def _handle_mms_connect_storm_case_object_config(self):
        self.MQTTOBJ = "默认MMS连接风暴流模板"
        self.Monitor = "默认监控器对象Ping"

    def _handle_vulnerability_scanner_case_object_config(self):
        self.VulnerabilityScannerMap = "默认漏洞数据库"
        self.Credential = ""

    def _handle_https_cps_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认156字节网页请求"
        self.SSLCACertConfig = ""
        self.SSLClientCertConfig = ""
        self.SSLServerCertConfig = "默认RSA算法1024位私钥带密码证书套件"

    def _handle_https_cc_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认156字节网页请求"
        self.SSLCACertConfig = ""
        self.SSLClientCertConfig = ""
        self.SSLServerCertConfig = "默认RSA算法1024位私钥带密码证书套件"

    def _handle_https_throughput_case_object_config(self):
        self.Monitor = "默认监控器对象Ping"
        self.Variate = "无"
        self.WebTestProjectName = "默认网络设备测试项目"
        self.FileObject = "默认156字节网页请求"
        self.SSLCACertConfig = ""
        self.SSLClientCertConfig = ""
        self.SSLServerCertConfig = "默认RSA算法1024位私钥带密码证书套件"

    def _handle_ssl_handshake_case_object_config(self):
        self.SSLCACertConfig = ""
        self.SSLClientCertConfig = ""
        self.SSLServerCertConfig = "默认RSA算法1024位私钥带密码证书套件"
        self.Monitor = "默认监控器对象Ping"

    def _handle_advanced_fuzzing_case_object_config(self):
        self.Fuzzing = "AMQP协议模糊测试模版"
        self.Monitor = "默认监控器对象Ping"

    def _handle_scenario_descrption_language_case_object_config(self):
        self.Descrption = "默认攻击场景检测对象"
        self.App_scenario = "默认应用场景对象"
        self.Malware = "默认恶意软件攻击对象"
        self.Mitre = "无"

    def _handle_web_scanner_case_object_config(self):
        self.Webattack = "默认SqliLabs靶场攻击列表"

    def set_descrption(self, value):
        self.Descrption = value

    def set_app_scenario(self, value):
        self.App_scenario = value

    def set_malware(self, value):
        self.Malware = value

    def set_mitre(self, value):
        self.Mitre = value

    def set_fuzzing(self, value):
        self.Fuzzing = value

    def set_ssl_ca_cert_config(self, value):
        self.SSLCACertConfig = value

    def set_ssl_client_cert_config(self, value):
        self.SSLClientCertConfig = value

    def set_ssl_server_cert_config(self, value):
        self.SSLServerCertConfig = value

    def set_vulnerability_scanner_map(self, value):
        self.VulnerabilityScannerMap = value

    def set_credential(self, value):
        self.Credential = value

    def set_mqtt_obj(self, value):
        self.MQTTOBJ = value

    def set_dns(self, value):
        self.Dns = value

    def set_dnskey(self, value):
        self.Dnskey = value

    def set_packet_payload_obj(self, value):
        self.PacketPayloadOBJ = value

    def set_monitor(self, value):
        self.Monitor = value

    def set_variate(self, value):
        self.Variate = value

    def set_web_test_project_name(self, value):
        self.WebTestProjectName = value

    def set_file_object(self, value):
        self.FileObject = value

    def to_dict(self):
        return self.__dict__


class BaseClientProfiles:
    def __init__(self, test_type, dut_role="Gateway"):

        # General Config
        self.SourcePortRange = "10000-65535"

        general_callback_dict = {
            "HttpCps": self._handle_http_cps_general_config,
            "HttpForceCps": self._handle_http_force_cps_general_config,
            "HttpCc": self._handle_http_cc_general_config,
            "UDPPayloadAttack": self._handle_udp_payload_attack_general_config,
            "HttpRequestFlood": self._handle_http_request_flood_general_config,
            "HTTPSlowRequestFlood": self._handle_http_slow_request_flood_general_config,
            "TcpSessionFlood": self._handle_tcp_session_flood_general_config,
            "HttpMultipleRequest": self._handle_http_multiple_request_general_config,
            "HttpRecursionRequest": self._handle_http_recursion_request_general_config,
            "HttpConcurrentSlowRead": self._handle_http_concurrent_slow_read_general_config,
            "HttpConcurrentSlowRequest": self._handle_http_concurrent_slow_request_general_config,
            "MmsConnectStorm": self._handle_mms_connect_storm_general_config,
            "NtpAmplificationAttack": self._handle_ntp_amplification_attack_general_config,
            "SSDPAttack": self._handle_ssdp_attack_general_config,
            "MemcachedAmplificationAttack": self._handle_memcached_amplification_attack_general_config,
            "Ipv4FragAttack": self._handle_ipv4_frag_attack_general_config,
            "MultiTypeFlood": self._handle_multi_type_flood_general_config,
            "TCPWinnuke": self._handle_tcp_winnuke_general_config,
            "UnicastStorm": self._handle_unicast_storm_general_config,
            "MulticastStorm": self._handle_multicast_storm_general_config,
            "BGPv4": self._handle_bgpv4_general_config,
            "BGPv6": self._handle_bgpv6_general_config,
            "Rfc2544Throughput": self._handle_rfc2544_throughput_general_config,
            "Rfc2544Latency": self._handle_rfc2544_latency_general_config,
            "Rfc2544LossRate": self._handle_rfc2544_loss_rate_general_config,
            "Rfc2544BackToBack": self._handle_rfc2544_back_to_back_general_config,
            "TCPSinglePacketAttack": self._handle_tcp_single_packet_attack_general_config,
            "HttpsFlood": self._handle_https_flood_general_config,
            "HttpsCps": self._handle_https_cps_general_config,
            "HttpsCc": self._handle_https_cc_general_config,
            "HttpsThroughput": self._handle_https_throughput_general_config,
            "SSLHandshake": self._handle_ssl_handshake_general_config,
            "DnsAmplificationAttack": self._handle_dns_amplification_attack_general_config,
            "WeakPasswordDetection": self._handle_weak_password_detection_general_config,
        }

        general_callback = general_callback_dict.get(test_type)
        if general_callback:
            general_callback()
        else:
            # general config is null
            pass

        # Client Parameters
        if dut_role == "Client":
            client_callback_dict = {
                "HttpsFlood": self._handle_https_flood_client_config
            }
            client_callback = client_callback_dict.get(test_type)
            if client_callback:
                client_callback()
            else:
                # client config is null
                pass

        # Proxy Parameters
        if dut_role == "Proxy":

            proxy_callback_dict = {
                "Rfc2544Throughput": self._handle_rfc2544_throughput_proxy_config,
                "Rfc2544LossRate": self._handle_rfc2544_loss_rate_proxy_config,
                "Rfc2544BackToBack": self._handle_rfc2544_back_to_back_proxy_config,
            }
            proxy_callback = proxy_callback_dict.get(test_type)
            if proxy_callback:
                proxy_callback()
            else:
                # proxy config is null
                pass

    def _handle_http_cps_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_force_cps_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_cc_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_udp_payload_attack_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_request_flood_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_slow_request_flood_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_tcp_session_flood_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_multiple_request_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_recursion_request_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_concurrent_slow_read_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_http_concurrent_slow_request_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_mms_connect_storm_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"

    def _handle_ntp_amplification_attack_general_config(self):
        self.RandomLength = 8
        self.Actions = {}

    def _handle_ssdp_attack_general_config(self):
        self.RandomLength = 8
        self.Actions = {}

    def _handle_memcached_amplification_attack_general_config(self):
        self.RandomLength = 8
        self.Actions = {}

    def _handle_ipv4_frag_attack_general_config(self):
        self.Actions = {}

    def _handle_multi_type_flood_general_config(self):
        self.Actions = {}

    def _handle_tcp_winnuke_general_config(self):
        self.Actions = {}

    def _handle_unicast_storm_general_config(self):
        self.Actions = {}

    def _handle_multicast_storm_general_config(self):
        self.Actions = {}

    def _handle_bgpv4_general_config(self):
        self.Actions = {}

    def _handle_bgpv6_general_config(self):
        self.Actions = {}

    def _handle_rfc2544_throughput_general_config(self):
        self.McoreDistributeTuplePolicy = "RSS_HASH"

    def _handle_rfc2544_latency_general_config(self):
        self.McoreDistributeTuplePolicy = "TUPLE_SID"

    def _handle_rfc2544_loss_rate_general_config(self):
        self.McoreDistributeTuplePolicy = "TUPLE_SID"

    def _handle_rfc2544_back_to_back_general_config(self):
        self.McoreDistributeTuplePolicy = "TUPLE_SID"

    def _handle_tcp_single_packet_attack_general_config(self):
        self.MonitorEnable = "no"
        self.MonitorIP = "17.1.1.222"
        self.Actions = {}

    def _handle_https_flood_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"
        self.SSLVersions = "TLSv1.2"
        self.SSLCiphers = ["AES128-SHA"]

    def _handle_https_cps_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"
        self.SSLQuietDown = "enable"
        self.SSLClientSessionCache = "no"
        self.ClientSSLAsyncMode = "no"
        self.SSLClientFixedEncCiphertext = "no"
        self.SSLVersions = "TLSv1.2"
        self.SSLCertVerify = "none"
        self.SSLVerifyErrorAction = 0
        self.SSLCiphers = ["AES128-GCM-SHA256"]

    def _handle_https_cc_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"
        self.SSLQuietDown = "enable"
        self.SSLClientSessionCache = "yes"
        self.ClientSSLAsyncMode = "no"
        self.SSLClientFixedEncCiphertext = "no"
        self.SSLVersions = "TLSv1.2"
        self.SSLCertVerify = "none"
        self.SSLVerifyErrorAction = 0
        self.SSLCiphers = ["AES128-GCM-SHA256"]

    def _handle_https_throughput_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"
        self.SSLQuietDown = "enable"
        self.SSLClientSessionCache = "yes"
        self.ClientSSLAsyncMode = "no"
        self.SSLClientFixedEncCiphertext = "no"
        self.SSLVersions = "TLSv1.2"
        self.SSLCertVerify = "none"
        self.SSLVerifyErrorAction = 0
        self.SSLCiphers = ["AES128-GCM-SHA256"]

    def _handle_ssl_handshake_general_config(self):
        self.Actions = {}
        self.RequestHeader = ["User-Agent: Firefox/41.0"]
        self.ClientCloseMode = "Reset"
        self.SSLQuietDown = "enable"
        self.SSLClientSessionCache = "yes"
        self.ClientSSLAsyncMode = "no"
        self.SSLClientFixedEncCiphertext = "no"
        self.SSLVersions = "TLSv1.2"
        self.SSLCertVerify = "none"
        self.SSLVerifyErrorAction = 0
        self.SSLCiphers = ["AES128-GCM-SHA256"]

    def _handle_https_flood_client_config(self):
        self.SSLCertVerify = "none"
        self.SSLVerifyErrorAction = 0

    def _handle_rfc2544_throughput_proxy_config(self):
        self.ProxyPort = "80"

    def _handle_rfc2544_loss_rate_proxy_config(self):
        self.ProxyPort = "80"

    def _handle_rfc2544_back_to_back_proxy_config(self):
        self.ProxyPort = "80"

    def _handle_dns_amplification_attack_general_config(self):
        self.SourcePortRange = "53"
        self.RandomLength = 8
        self.Actions = {}

    def _handle_weak_password_detection_general_config(self):
        del self.SourcePortRange

    def set_ssl_quiet_down(self, value):
        self.SSLQuietDown = value

    def set_ssl_client_session_cache(self, value):
        self.SSLClientSessionCache = value

    def set_client_ssl_async_mode(self, value):
        self.ClientSSLAsyncMode = value

    def set_ssl_client_fixed_enc_ciphertext(self, value):
        self.SSLClientFixedEncCiphertext = value

    def set_ssl_versions(self, value):
        self.SSLVersions = value

    def set_ssl_cert_verify(self, value):
        self.SSLCertVerify = value

    def set_ssl_verify_error_action(self, value):
        self.SSLVerifyErrorAction = value

    def set_ssl_ciphers(self, value):
        self.SSLCiphers = value

    def set_client_close_mode(self, value):
        self.ClientCloseMode = value

    def set_request_header(self, value):
        self.RequestHeader = value

    def set_monitor_enable(self, value: str):
        """
        Set monitor enable flag
        """
        if value not in ("yes", "no"):
            raise ValueError("Value must be 'yes' or 'no'")
        self.MonitorEnable = value

    def set_monitor_ip(self, value: str):
        """
        Set monitor IP address
        """
        import ipaddress
        try:
            ip_obj = ipaddress.IPv4Address(value)
            self.MonitorIP = str(ip_obj)
        except (ipaddress.AddressValueError, ValueError):
            raise ValueError(f"Invalid IP address: {value}")

    def set_mcore_distribute_tuple_policy(self, value):
        self.McoreDistributeTuplePolicy = value

    def set_actions(self, value):
        self.Actions = value

    def set_source_port_range(self, value):
        self.SourcePortRange = value

    def set_random_length(self, value):
        self.RandomLength = value

    def to_dict(self):
        return self.__dict__


class BaseServerProfiles:
    def __init__(self, test_type, dut_role="Gateway"):

        # General Config
        general_callback_dict = {
            "HttpCps": self._handle_http_cps_general_config,
            "HttpForceCps": self._handle_http_force_cps_general_config,
            "HttpCc": self._handle_http_cc_general_config,
            "HttpThroughput": self._handle_http_throughput_general_config,
            "HttpRequestFlood": self._handle_http_request_flood_general_config,
            "HTTPSlowRequestFlood": self._handle_http_slow_request_flood_general_config,
            "TcpSessionFlood": self._handle_tcp_session_flood_general_config,
            "HttpMultipleRequest": self._handle_http_multiple_request_general_config,
            "HttpRecursionRequest": self._handle_http_recursion_request_general_config,
            "HttpConcurrentSlowRead": self._handle_http_concurrent_slow_read_general_config,
            "HttpConcurrentSlowRequest": self._handle_http_concurrent_slow_request_general_config,
            "MmsConnectStorm": self._handle_mms_connect_storm_general_config,
            "HttpsCps": self._handle_https_cps_general_config,
            "HttpsCc": self._handle_https_cc_general_config,
            "HttpsThroughput": self._handle_https_cc_general_config,
            "SSLHandshake": self._handle_ssl_handshake_general_config,
            "HttpsFlood": self._handle_https_flood_general_config,
            "Ipv4FragAttack": self._handle_ipv4_frag_attack_general_config,
            "TCPSinglePacketAttack": self._handle_tcp_single_packet_attack_general_config,
            "MultiTypeFlood": self._handle_multi_type_flood_general_config,
            "UnicastStorm": self._handle_unicast_storm_general_config,
            "MulticastStorm": self._handle_multicast_storm_general_config,
            "WebScanner": self._handle_web_scanner_general_config,
            "VulnerabilityScanner": self._handle_vulnerability_scanner_general_config,
            "NetworkDiscovery": self._handle_network_discovery_general_config,
            "UDPSinglePacketAttack": self._handle_udp_single_packet_attack_general_config,
            "UDPPayloadAttack": self._handle_udp_payload_attack_general_config,
            "SipSinglePacketAttack": self._handle_sip_single_packet_attack_general_config,
            "DnsServiceAttack": self._handle_dns_service_attack_general_config,
            "SSDPAttack": self._handle_ssdp_attack_general_config,
            "DnsAmplificationAttack": self._handle_dns_amplification_attack_general_config,
            "NtpAmplificationAttack": self._handle_ntp_amplification_attack_general_config,
            "MemcachedAmplificationAttack": self._handle_memcached_amplification_attack_general_config,
            "TCPWinnuke": self._handle_tcp_winnuke_general_config,
            "AdvancedFuzzing": self._handle_advanced_fuzzing_general_config,
            "BGPv4": self._handle_bgpv4_general_config,
            "BGPv6": self._handle_bgpv6_general_config,
            "Rfc2544Throughput": self._handle_rfc2544_throughput_general_config,
            "Rfc2544Latency": self._handle_rfc2544_latency_general_config,
            "Rfc2544LossRate": self._handle_rfc2544_lossrate_general_config,
            "Rfc2544BackToBack": self._handle_rfc2544_backtoback_general_config,
            "WeakPasswordDetection": self._handle_weak_password_detection_general_config,
        }

        general_callback = general_callback_dict.get(test_type)
        if general_callback:
            general_callback()
        else:
            # general config is null
            pass

        # Server Parameters
        if dut_role == "Server":
            server_callback_dict = {
                "HttpCps": self._handle_dns_server_port_53_server_config,
                "HttpForceCps": self._handle_dns_server_port_53_server_config,
                "HttpCc": self._handle_dns_server_port_53_server_config,
                "HttpThroughput": self._handle_dns_server_port_53_server_config,
                "Rfc2544Throughput": self._handle_dns_server_port_53_server_config,
                "Rfc2544Latency": self._handle_dns_server_port_53_server_config,
                "Rfc2544LossRate": self._handle_dns_server_port_53_server_config,
                "Rfc2544BackToBack": self._handle_dns_server_port_53_server_config,
                "Ipv4FragAttack": self._handle_dns_server_port_53_server_config,
                "TCPSinglePacketAttack": self._handle_dns_server_port_53_server_config,
                "UDPSinglePacketAttack": self._handle_dns_server_port_53_server_config,
                "UDPPayloadAttack": self._handle_dns_server_port_53_server_config,
                "SipSinglePacketAttack": self._handle_dns_server_port_53_server_config,
                "DnsServiceAttack": self._handle_dns_server_port_53_server_config,
                "DnsAmplificationAttack": self._handle_dns_server_port_53_server_config,
                "SSDPAttack": self._handle_dns_server_port_53_server_config,
                "NtpAmplificationAttack": self._handle_dns_server_port_53_server_config,
                "MemcachedAmplificationAttack": self._handle_dns_server_port_53_server_config,
                "HttpRequestFlood": self._handle_dns_server_port_53_server_config,
                "ServerProfiles": self._handle_dns_server_port_53_server_config,
                "HttpsFlood": self._handle_dns_server_port_53_server_config,
                "HTTPSlowRequestFlood": self._handle_dns_server_port_53_server_config,
                "MultiTypeFlood": self._handle_dns_server_port_53_server_config,
                "TcpSessionFlood": self._handle_dns_server_port_53_server_config,
                "TCPWinnuke": self._handle_dns_server_port_53_server_config,
                "HttpMultipleRequest": self._handle_dns_server_port_53_server_config,
                "HttpRecursionRequest": self._handle_dns_server_port_53_server_config,
                "HttpConcurrentSlowRead": self._handle_dns_server_port_53_server_config,
                "HttpConcurrentSlowRequest": self._handle_dns_server_port_53_server_config,
                "MmsConnectStorm": self._handle_dns_server_port_53_server_config,

            }

            server_callback = server_callback_dict.get(test_type)
            if server_callback:
                server_callback()
            else:
                # server config is null
                pass

        # Client Parameters
        elif dut_role == "Client":

            client_callback_dict = {
                "HttpCps": self._handle_http_cps_client_config,
                "HttpForceCps": self._handle_http_force_cps_client_config,
                "HttpCc": self._handle_http_cc_client_config,
                "HttpThroughput": self._handle_http_throughput_client_config,
                "HttpsFlood": self._handle_https_flood_client_config,
                "HTTPSlowRequestFlood": self._handle_httpslow_request_flood_client_config,
                "HttpConcurrentSlowRead": self._handle_http_concurrent_slow_read_client_config,
                "HttpConcurrentSlowRequest": self._handle_http_concurrent_slow_request_client_config,

            }

            client_callback = client_callback_dict.get(test_type)
            if client_callback:
                client_callback()
            else:
                # client config is null
                pass

        elif dut_role == "Proxy":
            proxy_callback_dict = {
                "HttpCps": self._handle_http_cps_proxy_config,
                "HttpForceCps": self._handle_http_force_cps_proxy_config,
                "HttpCc": self._handle_http_cc_proxy_config,
                "HttpThroughput": self._handle_http_throughput_proxy_config,
            }

            proxy_callback = proxy_callback_dict.get(test_type)
            if proxy_callback:
                proxy_callback()
            else:
                # proxy config is null
                pass

        # Gateway Parameters
        elif dut_role == "Gateway":
            gateway_callback_dict = {
                "HttpCps": self._handle_http_cps_gateway_config,
                "HttpForceCps": self._handle_http_force_cps_gateway_config,
                "HttpCc": self._handle_http_cc_gateway_config,
                "HttpThroughput": self._handle_http_throughput_gateway_config,
                "UdpPps": self._handle_udp_pps_gateway_config,
                "TurboTcp": self._handle_turbo_tcp_gateway_config,
                "HTTPSlowRequestFlood": self._handle_http_slow_request_flood_gateway_config,
                "HttpConcurrentSlowRead": self._handle_http_concurrent_slow_read_gateway_config,
                "HttpConcurrentSlowRequest": self._handle_http_concurrent_slow_request_gateway_config,
            }

            gateway_callback = gateway_callback_dict.get(test_type)
            if gateway_callback:
                gateway_callback()
            else:
                # gateway config is null
                pass

    def _handle_http_cps_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_force_cps_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_cc_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_throughput_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_request_flood_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_slow_request_flood_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_tcp_session_flood_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_multiple_request_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_recursion_request_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_concurrent_slow_read_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_http_concurrent_slow_request_general_config(self):
        self.ServerPort = "80"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_mms_connect_storm_general_config(self):
        self.ServerPort = "102"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]

    def _handle_https_cps_general_config(self):
        self.ServerPort = "443"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.SSLServerSessionCache = "no"
        self.ServerSSLAsyncMode = "no"
        self.SSLServerFixedEncCiphertext = "no"
        self.SessionTicketExtention = "no"
        self.HttpReplyDelay = "0"
        self.ServerCertificate = "1024"

    def _handle_https_cc_general_config(self):
        self.ServerPort = "443"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]
        self.ServerRecvRqtTimeOut = 0
        self.Http1CloseDelayms = 500
        self.SSLServerSessionCache = "yes"
        self.ServerSSLAsyncMode = "no"
        self.SSLServerFixedEncCiphertext = "no"
        self.SessionTicketExtention = "yes"
        self.ServerCertificate = "1024"

    def _handle_ssl_handshake_general_config(self):
        self.ServerPort = "443"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.SSLServerSessionCache = "yes"
        self.ServerSSLAsyncMode = "no"
        self.SSLServerFixedEncCiphertext = "no"
        self.SessionTicketExtention = "yes"
        self.ServerCertificate = "1024"

    def _handle_https_flood_general_config(self):
        self.ServerPort = "443"
        self.ResponseHeader = [
            "Server: nginx/1.9.5",
            "Content-Type: text/html"
        ]
        self.ServerCertificate = "1024"

    def _handle_ipv4_frag_attack_general_config(self):
        self.ServerPort = "80"

    def _handle_tcp_single_packet_attack_general_config(self):
        self.ServerPort = "80"

    def _handle_multi_type_flood_general_config(self):
        self.ServerPort = "80"

    def _handle_unicast_storm_general_config(self):
        self.ServerPort = "80"

    def _handle_multicast_storm_general_config(self):
        self.ServerPort = "80"

    def _handle_web_scanner_general_config(self):
        self.ServerPort = "80"

    def _handle_vulnerability_scanner_general_config(self):
        self.ServerPort = "80"
        self.SpecifiedPort = "1-65535"

    def _handle_network_discovery_general_config(self):
        self.ServerPort = "80"
        self.SpecifiedPort = "1-65535"

    def _handle_udp_single_packet_attack_general_config(self):
        self.ServerPort = "69"

    def _handle_udp_payload_attack_general_config(self):
        self.ServerPort = "2641"
        self.ResponseHeader = ["Server: nginx/1.9.5", "Content-Type: text/html"]

    def _handle_sip_single_packet_attack_general_config(self):
        self.ServerPort = "5060"

    def _handle_dns_service_attack_general_config(self):
        self.ServerPort = "53"

    def _handle_ssdp_attack_general_config(self):
        self.ServerPort = "1900"

    def _handle_dns_amplification_attack_general_config(self):
        self.ServerPort = "10000-65535"

    def _handle_ntp_amplification_attack_general_config(self):
        self.ServerPort = "123"

    def _handle_memcached_amplification_attack_general_config(self):
        self.ServerPort = "11211"

    def _handle_tcp_winnuke_general_config(self):
        self.ServerPort = "139"

    def _handle_advanced_fuzzing_general_config(self):
        self.ServerPort = "5672"

    def _handle_bgpv4_general_config(self):
        self.ServerPort = "6001"

    def _handle_bgpv6_general_config(self):
        self.ServerPort = "6001"

    def _handle_rfc2544_throughput_general_config(self):
        self.ServerPort = "6006"

    def _handle_rfc2544_latency_general_config(self):
        self.ServerPort = "6006"

    def _handle_rfc2544_lossrate_general_config(self):
        self.ServerPort = "6006"

    def _handle_rfc2544_backtoback_general_config(self):
        self.ServerPort = "6006"

    def _handle_weak_password_detection_general_config(self):
        self.ServerPort = "502"

    def _handle_dns_server_port_53_server_config(self):
        self.DNSServerPort = "53"

    def _handle_http_cps_client_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_http_force_cps_client_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_http_cc_client_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_http_throughput_client_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_https_flood_client_config(self):
        self.SSLCertVerify = "none"
        self.SSLVerifyErrorAction = 0
        self.SSLVersions = "NetiGMv1.1"

    def _handle_httpslow_request_flood_client_config(self):
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = "no"

    def _handle_http_concurrent_slow_read_client_config(self):
        self.ServerCloseMode = "3Way_Fin"
        self.HttpReplyDelay = "0"

    def _handle_http_concurrent_slow_request_client_config(self):
        self.ServerCloseMode = "3Way_Fin"
        self.HttpReplyDelay = "0"

    def _handle_http_cps_proxy_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_http_force_cps_proxy_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_http_cc_proxy_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_http_throughput_proxy_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"
        self.HttpProxyProtocolEn = 'no'

    def _handle_http_cps_gateway_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"

    def _handle_http_force_cps_gateway_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"

    def _handle_http_cc_gateway_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"

    def _handle_http_throughput_gateway_config(self):
        self.ServerRecvRqtTimeOut = 300000
        self.Http1CloseDelayms = 500
        self.ServerCloseMode = "3Way_Fin"

    def _handle_udp_pps_gateway_config(self):
        self.ServerPort = "80"

    def _handle_turbo_tcp_gateway_config(self):
        self.ServerPort = "6000"
        self.ServerCloseMode = "Reset"

    def _handle_http_slow_request_flood_gateway_config(self):
        self.ServerCloseMode = "3Way_Fin"

    def _handle_http_concurrent_slow_read_gateway_config(self):
        self.ServerCloseMode = "3Way_Fin"
        self.HttpReplyDelay = "0"

    def _handle_http_concurrent_slow_request_gateway_config(self):
        self.ServerCloseMode = "3Way_Fin"
        self.HttpReplyDelay = "0"

    def set_server_recv_rqt_timeout(self, value):
        self.ServerRecvRqtTimeOut = value

    def set_http1_close_delayms(self, value):
        self.Http1CloseDelayms = value

    def set_ssl_server_session_cache(self, value):
        self.SSLServerSessionCache = value

    def set_server_ssl_async_mode(self, value):
        self.ServerSSLAsyncMode = value

    def set_ssl_server_fixed_enc_ciphertext(self, value):
        self.SSLServerFixedEncCiphertext = value

    def set_session_ticket_extention(self, value):
        self.SessionTicketExtention = value

    def set_server_certificate(self, value):
        self.ServerCertificate = value

    def set_session_ticket_extension(self, value):
        self.SessionTicketExtention = value

    def set_http_reply_delay(self, value):
        self.HttpReplyDelay = value

    def set_specified_port(self, value):
        self.SpecifiedPort = value

    def set_server_close_mode(self, value):
        self.ServerCloseMode = value

    def set_dns_server_port(self, value):
        self.DNSServerPort = value

    def set_http_proxy_protocol_en(self, value):
        self.HttpProxyProtocolEn = value

    def set_ssl_cert_verify(self, value):
        self.SSLCertVerify = value

    def set_ssl_verify_error_action(self, value):
        self.SSLVerifyErrorAction = value

    def set_ssl_versions(self, value):
        self.SSLVersions = value

    def set_server_port(self, value):
        self.ServerPort = value

    def set_server_recvrqt_timeout(self, value):
        self.ServerRecvRqtTimeOut = value

    def to_dict(self):
        return self.__dict__


class GenericTestCaseModel:
    def __init__(self, test_type: str, dut_role: str):
        self.Loads = BaseLoads(test_type)
        self.CaseObject = BaseCaseObject(test_type)
        self.ClientProfiles = BaseClientProfiles(test_type, dut_role=dut_role)
        self.ServerProfiles = BaseServerProfiles(test_type, dut_role=dut_role)

    def to_dict(self):
        return {
            "Loads": self.Loads.to_dict(),
            "CaseObject": self.CaseObject.to_dict(),
            "ClientProfiles": self.ClientProfiles.to_dict(),
            "ServerProfiles": self.ServerProfiles.to_dict()
        }


class PortConfig:

    def _handle_bgp_v6_config(self, config_dict):

        port_side = config_dict.get("port_side", "")
        dut_role = config_dict.get("dut_role", "")
        proxy_mode = config_dict.get("proxy_mode", "")

        if port_side == "client":
            network_subnets_obj = ClientSubnet(dut_role, proxy_mode, 6, 'no')
            network_subnets_obj.__dict__.update({"SubnetNumber": "1"})
            self.NetworkSubnets = [network_subnets_obj.to_dict()]
        if port_side == "server":
            network_subnets_obj = ServerSubnet(6, 'no')
            network_subnets_obj.__dict__.update({"SubnetNumber": "1"})
            self.NetworkSubnets = [network_subnets_obj.to_dict()]

        del self.SimUserSpeedLimit

    def _handle_scenario_descrption_language_config(self, config_dict):

        port_side = config_dict.get("port_side", "")
        dut_role = config_dict.get("dut_role", "")
        proxy_mode = config_dict.get("proxy_mode", "")

        if port_side == "client":
            self.NetworkSubnets = [ClientSubnet(dut_role, proxy_mode, server_address_format='Port').to_dict(),
                                   ClientSubnet(dut_role, proxy_mode, 6, 'no', server_address_format='Port').to_dict()]

    def _handle_rfc2544_throughput_config(self):
        self.PortStreamTemplate = PortStreamTemplate().to_dict()

    def _handle_rfc2544_latency_config(self):
        del self.PortSpeedLimit
        del self.SimUserSpeedLimit
        self.PortStreamTemplate = PortStreamTemplate().to_dict()
        self.PortRXRSS = "yes"
        self.PortLinkSpeedNow = 10000
        self.PortModuleType = "100G_40G_QSFP28"

    def _handle_rfc2544_loss_rate_config(self):
        self.PortStreamTemplate = PortStreamTemplate().to_dict()

    def _handle_rfc2544_back_to_back_config(self):
        self.PortStreamTemplate = PortStreamTemplate().to_dict()

    def _handle_http_cc_config(self):
        del self.SimUserSpeedLimit

    def _handle_http_force_cps_config(self):
        del self.SimUserSpeedLimit

    def _handle_web_scanner_config(self):
        del self.SimUserSpeedLimit

    def _handle_bgp_v4_config(self, config_dict):
        port_name = config_dict.get("port_name", "")

        del self.SimUserSpeedLimit
        self.AdditionalFields = AdditionalFields(port_name).to_dict()
        self.route_strm_cfg = RouteStrmCfg().to_dict()
        self.bfdConfig = BfdConfig().to_dict()
        self.PortRXRSS = "yes"

    def __init__(self, port_name, port_side, case_config):
        dut_role = case_config.get("DUTRole", "")
        proxy_mode = case_config.get("ProxyMode", "")
        test_type = case_config.get("TestType", "")

        # General Config
        if port_side == "client":
            self.NetworkSubnets = [ClientSubnet(dut_role, proxy_mode).to_dict(),
                                   ClientSubnet(dut_role, proxy_mode, 6, 'no').to_dict()]
        elif port_side == "server":
            self.NetworkSubnets = [ServerSubnet().to_dict(), ServerSubnet(6, 'no').to_dict()]

        self.PacketCapture = [PacketCapture().to_dict()]

        self.Interface = port_name
        self.PortEnable = "yes"
        self.PortSide = port_side

        # Dpdk Config
        if ToolsUtils.is_dpdk_test_type(test_type):
            self.VirtualRouterConfig = VirtualRouterConfig(side=port_side, test_type=test_type, port_name=port_name).to_dict()
            self.NetworkZone = NetworkZone(test_type=test_type).to_dict()
            self.PortSpeedLimit = [PortSpeedLimit(test_type).to_dict()]
            self.PacketFilter = [PacketFilter().to_dict()]
            self.VXLANTunnel = VXLANTunnel().to_dict()
            self.GTPUTunnel = GTPUTunnel().to_dict()
            self.MsgFragSet = MsgFragSet().to_dict()
            self.MACSEC = MACSEC().to_dict()
            self.QoSConfiguration = QoSConfiguration().to_dict()

            self.PortSpeedDetectMode = "Autoneg"
            self.MacMasquerade = "A2:01#disabled"
            self.TesterPortMacAddress = "68:91:d0:66:b1:b6#disabled"
            self.NextPortMacMethod = "ARP_NSNA#disabled"
            self.PortRXRSS = "no"
            self.PortLinkSpeedNow = 10000
            self.PortModuleType = "100G_40G_QSFP28"
            self.HeadChecksumConf = {
                "IPV4HeadChecksumType": "auto",
                "TCPHeadChecksumType": "auto",
                "UDPHeadChecksumType": "auto"
            }
            self.nb_txd = 4096
            self.nb_rxd = 4096
            self.nictype = "PERF"
            self.device = "NetiTest IT2X010GF47LA 1G/10G SmartNIC"
            self.sendqueue = "4"
            self.receivequeue = "4"
            self.CoreBind = "2"
            self.OuterVlanID = "1#disabled"
            self.QinqType = "0x88A8#disabled"
            self.VlanID = "1#disabled"

        # DDos Config
        if not ToolsUtils.is_ddos_type(test_type):
            self.SimUserSpeedLimit = [SimUserSpeedLimit().to_dict()]

        # TestType Special Config
        port_config_callback_dict = {
            "BGPv6": self._handle_bgp_v6_config,
            'ScenarioDescrptionLanguage': self._handle_scenario_descrption_language_config,
            'BGPv4': self._handle_bgp_v4_config,
        }

        no_param_port_config_callback_dict = {
            'Rfc2544Throughput': self._handle_rfc2544_throughput_config,
            'Rfc2544Latency': self._handle_rfc2544_latency_config,
            'Rfc2544LossRate': self._handle_rfc2544_loss_rate_config,
            'Rfc2544BackToBack': self._handle_rfc2544_back_to_back_config,
            'HttpCc': self._handle_http_cc_config,
            'HttpForceCps': self._handle_http_force_cps_config,
            'WebScanner': self._handle_web_scanner_config,
        }

        if test_type in port_config_callback_dict:
            config_dict = {
                "test_type": test_type,
                "port_side": port_side,
                "dut_role": dut_role,
                "proxy_mode": proxy_mode,
                "port_name": port_name,
            }

            port_config_callback_dict[test_type](config_dict)

        elif test_type in no_param_port_config_callback_dict:
            no_param_port_config_callback_dict[test_type]()

    def set_port_core_bind(self, core_bind):
        self.CoreBind = core_bind

    def to_dict(self):
        # return ToolsUtils.to_dict(self)
        return self.__dict__


class CustomPortConfig:
    def __init__(self, port_name, port_side, port_json, config_json):
        dut_role = config_json.get("DUTRole", "")
        proxy_mode = config_json.get("ProxyMode", "")
        test_type = config_json.get("TestType", "")

        self.NetworkSubnets = port_json.get("NetworkSubnets")

        # VirtualRouterConfig
        virtual_router_config_list = []
        for virtual_router_config_json in port_json.get("VirtualRouterConfig", []):
            subnet_version = virtual_router_config_json.get("NetworkZone")
            virtual_router_config_obj = VirtualRouterConfigDict(version=subnet_version)
            virtual_router_config_obj.__dict__.update(virtual_router_config_json)
            virtual_router_config_list.append(virtual_router_config_obj)
        self.VirtualRouterConfig = VirtualRouterConfig(virtual_router_config_list).to_dict()

        # NetworkZone
        network_zone_list = []
        for network_zone_json in port_json.get("NetworkZone", []):
            subnet_version = network_zone_json.get("NetworkZone")
            network_zone_obj = NetworkZoneDict(version=subnet_version)
            network_zone_obj.__dict__.update(network_zone_json)
            network_zone_list.append(network_zone_obj)
        self.NetworkZone = NetworkZone(network_zone_list).to_dict()

        # speed limit
        self.PortSpeedLimit = []
        for port_speed_limit_json in port_json.get("PortSpeedLimit", []):
            port_speed_limit_obj = PortSpeedLimit(test_type)
            port_speed_limit_obj.__dict__.update(port_speed_limit_json)
            self.PortSpeedLimit.append(port_speed_limit_obj.to_dict())

        # packet capture
        self.PacketCapture = []
        for packet_capture_json in port_json.get("PacketCapture", []):
            packet_capture_obj = PacketCapture()
            packet_capture_obj.__dict__.update(packet_capture_json)
            self.PacketCapture.append(packet_capture_obj.to_dict())

        self.PacketFilter = []
        for packet_filter_json in port_json.get("PacketFilter", []):
            packet_filter_obj = PacketFilter()
            packet_filter_obj.__dict__.update(packet_filter_json)
            self.PacketFilter.append(packet_filter_obj.to_dict())

        # VXLAN
        if port_json.get("VXLANTunnel", {}):
            self.VXLANTunnel = VXLANTunnel()
            self.VXLANTunnel.__dict__.update(port_json.get("VXLANTunnel", {}))
            self.VXLANTunnel = self.VXLANTunnel.to_dict()

        if port_json.get("GTPUTunnel", {}):
            self.GTPUTunnel = GTPUTunnel()
            self.GTPUTunnel.__dict__.update(port_json.get("GTPUTunnel", {}))
            self.GTPUTunnel = self.GTPUTunnel.to_dict()

        if port_json.get("MsgFragSet", {}):
            self.MsgFragSet = MsgFragSet()
            self.MsgFragSet.__dict__.update(port_json.get("MsgFragSet", {}))
            self.MsgFragSet = self.MsgFragSet.to_dict()

        if port_json.get("MACSEC", {}):
            self.MACSEC = MACSEC()
            self.MACSEC.__dict__.update(port_json.get("MACSEC", {}))
            self.MACSEC = self.MACSEC.to_dict()

        if port_json.get("QoSConfiguration", {}):
            self.QoSConfiguration = QoSConfiguration()
            self.QoSConfiguration.__dict__.update(port_json.get("QoSConfiguration", {}))
            self.QoSConfiguration = self.QoSConfiguration.to_dict()

        # Other keys
        self.Interface = port_name
        self.PortEnable = port_json.get("PortEnable")
        self.PortSide = port_side

        if ToolsUtils.is_dpdk_test_type(test_type):
            self.PortSpeedDetectMode = port_json.get("PortSpeedDetectMode")
            self.TesterPortMacAddress = port_json.get("TesterPortMacAddress")
            self.NextPortMacMethod = port_json.get("NextPortMacMethod")
            self.PortRXRSS = port_json.get("PortRXRSS")
            self.HeadChecksumConf = port_json.get("HeadChecksumConf")
            self.nb_txd = port_json.get("nb_txd")
            self.nb_rxd = port_json.get("nb_rxd")
            self.nictype = port_json.get("nictype")
            self.device = port_json.get("device")
            self.sendqueue = port_json.get("sendqueue")
            self.receivequeue = port_json.get("receivequeue")
            self.CoreBind = port_json.get("CoreBind")
            self.OuterVlanID = port_json.get("OuterVlanID")
            self.QinqType = port_json.get("QinqType")
            self.VlanID = port_json.get("VlanID")
            self.driver = port_json.get("driver")

    def set_port_core_bind(self, core_bind):
        self.CoreBind = core_bind

    def to_dict(self):
        # return ToolsUtils.to_dict(self)
        return self.__dict__


class HttpClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token = None

    def import_file(self, path, filename='', test_type=''):
        import mimetypes
        url = f"{self.base_url}{path}"
        headers = {"Accept-Language": "zh-CN,zh;q=0.9"}
        # Guess the file type
        file_type = mimetypes.guess_type(filename)[0]
        files = {
            'file': (filename, open(filename, 'rb'), file_type),
            'testType': (None, test_type)
        }
        response = self.session.post(url, headers=headers, files=files)
        if response.status_code != 200:
            msg = f"Request failed: {response.status_code} - {response.text}"
            logger.error(msg)
            sys.exit()
        else:
            ret = response.json()
            error_code = ret.get("ErrorCode", 0)
            error_message = ret.get("ErrorMessage", "")
            if error_code != 0:
                logger.error(f"The upload of the file failed. ErrorCode is {error_code}, The reason is: {error_message}")
            return error_code, error_message

    def download_file(self, path, params=None, filepath="./"):
        import re
        import datetime
        url = f"{self.base_url}{path}"
        response = self.session.get(url, params=params)
        if response.status_code != 200:
            msg = f"Request failed: {response.status_code} - {response.text}"
            logger.error(msg)
            sys.exit()
        content_disposition = response.headers.get("content-disposition")
        specific_ret = re.search(r'filename="(.*)"', content_disposition)
        normal_ret = re.search(r'filename=(.*)', content_disposition)
        if specific_ret or normal_ret:
            ret = specific_ret if specific_ret else normal_ret
            file_name = ret.group(1).replace(":", "_")
        else:
            file_name = datetime.datetime.now().strftime("%Y%m%d%H%M%S.zip")

        f = open(os.path.join(filepath, file_name), "wb")
        for chunk in response.iter_content(chunk_size=512):
            if chunk:
                f.write(chunk)

    def get_download(self, path, params=None, file_path=None):
        """
        Send file download request and save to local

        Args:
            path (str): API endpoint path
            params (dict): Request parameters
            file_path (str): Local file save path

        Returns:
            str: Saved file path

        Raises:
            Exception: Throws when request fails or file save fails
        """
        url = f"{self.base_url}{path}"
        headers = self._build_headers()

        try:
            # Send streaming request
            response = self.session.get(url, headers=headers, params=params, stream=True)
            if response.status_code != 200:
                msg = f"File download failed: {response.status_code} - {response.text}"
                logger.error(msg)
                raise Exception(msg)

            # Write to local file
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:  # Filter keep-alive chunks
                        f.write(chunk)

            logger.info(f"File download completed, saved to: {file_path}")
            return file_path

        except IOError as e:
            logger.exception("File write failed")
            raise Exception(f"Unable to write file: {str(e)}")
        except Exception as e:
            logger.error(f"Download request error: {str(e)}")
            raise Exception(f"File write failed: {str(e)}")

    def login(self, payload):
        url = f"{self.base_url}/api/user/login"
        logger.info(f"Login URL: {url}")
        response = self.session.post(url, json=payload)
        if response.status_code == 200:
            logger.info("Login successful.")
            self.user = payload["name"]
            data = response.json().get("Data")
            self.token = response.json().get("token")
            self.encrpt_name = data.get("encrpt_name")
            self.encrpt_role = data.get("encrpt_role")
        else:
            msg = f"Login failed: {response.status_code} - {response.text}"
            logger.error(msg)
            raise Exception(msg)

    def get(self, path, params=None):
        url = f"{self.base_url}{path}"
        headers = self._build_headers()
        response = self.session.get(url, headers=headers, params=params)
        if response.status_code != 200:
            msg = f"Request failed: {response.status_code} - {response.text}"
            logger.error(msg)
            raise Exception(msg)

        return response.json()

    def post(self, path, data=None):
        url = f"{self.base_url}{path}"
        headers = self._build_headers()
        response = self.session.post(url, headers=headers, json=data)
        if response.status_code != 200:
            msg = f"Request failed: {response.status_code} - {response.text}"
            logger.error(msg)
            raise Exception(msg)

        return response.json()

    def _build_headers(self):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers


class TestCaseBuilder:
    def __init__(self, host, test_type, dut_role, proxy_mode):
        self.base = None
        self.host = host
        self.test_type = test_type
        self.dut_role = dut_role
        self.proxy_mode = proxy_mode
        self.case_model = TestFactory.create(test_type, dut_role)

    def build(self):
        base = BaseCase()
        self.base = base
        base.set_dut_role(self.dut_role)
        base.set_proxy_mode(self.proxy_mode)
        base.set_test_type(self.test_type)
        data = base.to_dict()
        data["Specifics"] = self._build_specifics()
        data["NetworkConfig"] = self._build_network_config()
        return data

    def _build_specifics(self):
        specifics = {"TestType": self.test_type}
        for field in ["Loads", "CaseObject", "ClientProfiles", "ServerProfiles"]:
            obj = getattr(self.case_model, field)
            specifics[field] = obj.to_dict()
        return [specifics]

    def _build_network_config(self):
        return {
            "NetworkControl": NetworkControlConfig(self.test_type).to_dict(),
            "SlaveHost": [{"Host": self.host, "Ports": []}]
        }


class TestCase:
    def __init__(self, host, http_client, test_type, dut_role, proxy_mode):
        self.report_id = None
        self.test_type = test_type
        self.dut_role = dut_role
        self.host = host
        self.client = http_client
        self.case_id = None
        # self.case_config = TestCaseBuilder(self.host, test_type, dut_role, proxy_mode).build()
        self.case_object = TestCaseBuilder(self.host, test_type, dut_role, proxy_mode)
        self.case_config = self.case_object.build()
        self.port_list = []
        self.get_default_values()

    def _handle_user_apply_memory(self, user_apply_memory: int):
        """
        * Handle user apply memory
        """
        if user_apply_memory:
            user_apply_memory = int(user_apply_memory)
            if user_apply_memory < 2 or user_apply_memory > self.case_object.case_model.Loads.CaseAssignMemoryGB:
                msg = "User apply memory must be in the range of 2-{} GB".format(
                    self.case_object.case_model.Loads.CaseAssignMemoryGB)
                logger.error(msg)
                raise ValueError(msg)
        self.case_object.case_model.Loads.set_user_apply_memory_mb(user_apply_memory)

    def _handle_test_duration(self, test_duration: int):
        """
        * Handle test duration
        """
        if test_duration:
            test_duration = int(test_duration)
            if test_duration < 1:
                msg = "Test duration must be greater than 0"
                logger.error(msg)
                raise ValueError(msg)
        self.case_object.base.set_test_duration(test_duration)

    def _handle_server_port(self, server_port: int):
        """
        * Handle server port
        """
        if server_port is None:
            return

        self.case_object.case_model.ServerProfiles.set_server_port(server_port)

    def _handle_case_object(self, case_object_dict):
        """
        * Handle case object
        """
        if not case_object_dict:
            return

        monitor = case_object_dict.get("Monitor")
        variate = case_object_dict.get("Variate")
        web_test_project_name = case_object_dict.get("WebTestProjectName")
        file_object = case_object_dict.get("FileObject")

        if monitor:
            self.case_object.case_model.CaseObject.set_monitor(monitor)
        if variate:
            self.case_object.case_model.CaseObject.set_variate(variate)
        if web_test_project_name:
            self.case_object.case_model.CaseObject.set_web_test_project_name(web_test_project_name)
        if file_object:
            self.case_object.case_model.CaseObject.set_file_object(file_object)

    def _handle_sim_user(self, sim_user: int):
        """
        * Handle sim user
        """
        if sim_user:
            sim_user = int(sim_user)
            if sim_user < 1:
                msg = "sim user must be greater than 0"
                logger.error(msg)
                raise ValueError(msg)
        self.case_object.case_model.Loads.set_sim_user(sim_user)

    def _handle_latency(self, latency: str):
        """
        * Handle latency
        """
        if not latency:
            return

        self.case_object.case_model.Loads.set_latency(latency)

    def _handle_dual_flow_mode(self, dual_flow_mode: str):
        """
        * Handle dual_flow_mode
        """
        if not dual_flow_mode:
            return

        self.case_object.case_model.Loads.set_dual_flow_mode(dual_flow_mode)

    def _handle_frame_size_policy(self, frame_size_policy):
        """
        * Handle frame_size_policy
        """
        if not frame_size_policy:
            return

        self.case_object.case_model.Loads.set_frame_size_policy(frame_size_policy)

    def _handle_cycle_duration_policy(self, cycle_duration_policy):
        """
        * Handle _handle_cycle_duration_policy
        """
        if not cycle_duration_policy:
            return

        self.case_object.case_model.Loads.set_cycle_duration_policy(cycle_duration_policy)

    def _apply_port_limit_value(self, port_name: str, limit_value_str: str):
        # set core binding
        for port in self.port_list:
            if port.Interface == port_name:
                for port_limit_dict in port.PortSpeedLimit:
                    if self.test_type == "HttpForceCps":
                        port_limit_dict["StrongLimitValue"] = int(limit_value_str)
                    else:
                        port_limit_dict["SpeedLimit"] = int(limit_value_str)

    def _handle_port_limit_value(self, *args):
        logger.info("Handling Port Limit Value")
        for port_limit_str in args:
            port_name, limit_value_str = self._parse_core_str(port_limit_str)
            self._apply_port_limit_value(port_name, limit_value_str)
            logger.info(f"Port {port_name} limit value set to {limit_value_str}")

    def _handle_load_limit_policy(self, load_limit_policy):
        """
        * Handle load_limit_policy
        """
        if not load_limit_policy:
            return

        self.case_object.case_model.Loads.set_load_limit_policy(load_limit_policy)

    def _handle_index_start(self, index_start: int):
        """
        * Handle index start
        """
        if index_start is None:
            return

        self.case_object.case_model.Loads.set_index_start(index_start)

    def _handle_index_end(self, index_end=""):

        if not index_end:
            index_end = ""

        self.case_object.case_model.Loads.set_index_end(index_end)

    def _handle_fuzz_db_keep_only_n_pass_cases(self, count: int):
        """
        * Handle fuzz db keep only N pass cases
        """
        if count is None:
            return

        self.case_object.case_model.Loads.set_fuzz_db_keep_only_n_pass_cases(count)

    def _handle_reuse_target_connection(self, reuse: str):
        """
        * Handle reuse target connection
        """
        if not reuse:
            return

        self.case_object.case_model.Loads.set_reuse_target_connection(reuse)

    def _handle_fuzzing(self, fuzzing):
        """
        * Handle AdvancedFuzzing fuzzing
        """
        if not fuzzing:
            return

        self.case_object.case_model.CaseObject.set_fuzzing(fuzzing)

    def _handle_test_mode(self, test_mode):
        """
        * Handle Base test_mode
        """
        if not test_mode:
            return

        self.case_object.base.set_test_mode(test_mode)

    def _handle_huge_page_memory(self, huge_page_memory: int):
        """
        * Handle huge page memory
        """
        if huge_page_memory:
            huge_page_memory = int(huge_page_memory)
            if huge_page_memory < 10 or huge_page_memory > 95:
                msg = "Huge page memory must be greater than 10 and less than 95"
                logger.error(msg)
                raise ValueError(msg)
        self.case_object.case_model.Loads.set_dpdk_huge_memory_pct(huge_page_memory)

    def _handle_case_assign_memory_gb(self, case_assign_memory_gb: int):
        """
        * Handle case running memory
        """
        if case_assign_memory_gb:
            case_assign_memory_gb = int(case_assign_memory_gb)
            if case_assign_memory_gb < 2 or case_assign_memory_gb > 28:
                msg = "Case Assign Memory GB must be greater than 2 and less than 28"
                logger.error(msg)
                raise ValueError(msg)
        self.case_object.case_model.Loads.set_case_assign_memory_gb(case_assign_memory_gb)

    def _handle_test_name(self, test_name: str):
        """
        * Handle test name
        """
        if not test_name:
            return

        self.case_object.base.set_test_name(test_name)

    def _handle_descrption(self, descrption: str):
        """
        * Handle descrption
        """
        if not descrption:
            return

        self.case_object.case_model.CaseObject.set_descrption(descrption)

    def _handle_app_scenario(self, app_scenario: str):
        """
        * Handle app_scenario
        """
        if not app_scenario:
            return

        self.case_object.case_model.CaseObject.set_app_scenario(app_scenario)

    def _handle_malware(self, malware: str):
        """
        * Handle malware
        """
        if not malware:
            return

        self.case_object.case_model.CaseObject.set_malware(malware)

    def _handle_mitre(self, mitre: str):
        """
        * Handle mitre
        """
        if not mitre:
            return

        self.case_object.case_model.CaseObject.set_mitre(mitre)

    def _handle_send_wait_time(self, value: int):
        """
        * Handle send wait time
        """
        if value is None:
            return

        self.case_object.case_model.Loads.set_send_wait_time(value)

    def _handle_send_num_cyles(self, value: int):
        """
        * Handle send num cyles
        """
        if value is None:
            return

        self.case_object.case_model.Loads.set_send_num_cyles(value)

    def _handle_scenario_timeout(self, value: int):
        """
        * Handle scenario timeout
        """
        if value is None:
            return

        self.case_object.case_model.Loads.set_scenario_timeout(value)

    def _handle_scenario_interval(self, value: int):
        """
        * Handle scenario interval
        """
        if value is None:
            return

        self.case_object.case_model.Loads.set_scenario_interval(value)

    def _handle_sock_recv_timeout(self, value: int):
        """
        * Handle socket receive timeout
        """
        if value is None:
            return

        self.case_object.case_model.Loads.set_sock_recv_timeout(value)

    def _handle_maximum_iterative_cycle(self, value: int):
        if value:
            value = int(value)
            if value < 1 or value > 100:
                msg = "test retry count must be between 1 and 100"
                logger.error(msg)
                raise ValueError(msg)
        self.case_object.case_model.Loads.set_maximum_iterative_cycle(value)

    @staticmethod
    def parse_port_list(port_str):
        return port_str.split(',') if port_str else []

    def check_cpu_cores_is_valid(self):
        """
        * Verify if CPU core binding is valid
        :return:
        """
        # Check if other ports have bound the same cores
        for port in self.port_list:
            if port.CoreBind:
                one_core_set = set(port.CoreBind.split(','))
                for other_port in self.port_list:
                    other_core_set = set(other_port.CoreBind.split(','))
                    if other_port != port and one_core_set & other_core_set:
                        msg = f"CPU core {port.CoreBind}: duplicate binding"
                        logger.error(msg)
                        raise ValueError(msg)

    def get_default_values(self):
        """
        Get and replace default values from the tester

        Returns:
            dict: Updated configuration dictionary

        Raises:
            Exception: When API request fails
        """
        # Get system information
        self._get_system_infos()

        # Get DPDK huge page memory percentage
        self._get_dpdk_memory_percentage()

        # Get specific test type configuration
        if self.test_type in ["HttpCc", "HttpsCc"]:
            self._get_concurrent_connection_config()

        return self.case_config

    def _get_system_infos(self):
        """
        * Get system information and update configuration
        """
        infos_ret = self.client.get("/api/system/infos")
        if infos_ret.get("ErrorCode") != 0:
            msg = f"get system infos failed: {infos_ret.get('ErrorMessage')}"
            logger.error(msg)
            raise Exception(msg)

        if "Data" not in infos_ret or not infos_ret["Data"]:
            msg = f"get system infos Data failed"
            logger.error(msg)
            raise Exception(msg)

        infos_dict = infos_ret["Data"]
        self.case_config["WorkMode"] = infos_dict["WorkMode"]["workMode"]
        self.case_config["DutSystemVersion"] = infos_dict["Version"]
        self.case_config["ImageVersion"] = infos_dict["Version"].split()[1]

        # Update memory configuration
        self._update_memory_config(infos_dict["MemoryMgmt"]["Used"])
        return infos_ret

    def _update_memory_config(self, memory_info: list):
        """
        * Update memory configuration information
        """
        for mem in memory_info:
            if mem["ResourceUser"] == self.client.user:
                self.case_config["Specifics"][0]["Loads"]["CaseAssignMemoryGB"] = mem["ResourceOccupy"]
                self.case_config["Specifics"][0]["Loads"]["UserApplyMemoryMB"] = mem["ResourceOccupy"]
                break

    def _get_dpdk_memory_percentage(self):
        """
        * Get DPDK huge page memory percentage
        """
        dpdk_huge_memory_pct = self.client.get("/api/case/DpdkHugeMemoryPct", {"testType": self.test_type})
        if dpdk_huge_memory_pct.get("ErrorCode") != 0:
            msg = f"get dpdk huge memory pct failed: {dpdk_huge_memory_pct.get('ErrorMessage')}"
            logger.error(msg)
            raise Exception(msg)

        # Huge page memory percentage
        default_value = dpdk_huge_memory_pct.get("Data", {}).get("def", 70)
        self.case_config["Specifics"][0]["Loads"]["DPDKHugeMemoryPct"] = default_value

    def _get_concurrent_connection_config(self):
        """
        * Get concurrent connection configuration
        """
        cc_cfg = self.client.get("/api/case/conn/cfg", {"testType": self.test_type})
        # Concurrent connections
        default_value = cc_cfg.get("Data", {}).get("def", 1296000)
        self.case_config["Specifics"][0]["Loads"]["ConcurrentConnection"] = default_value

    def update_port_default_values(self):
        """
        Update port default values

        Get port information from API and update port configuration, including device information,
        driver, queues and core binding, etc.

        Raises:
            Exception: When API request fails
        """
        logger.info("Start to update port default values")
        # Get port and NIC information
        port_info_ret, nic_infos_ret = self._get_port_and_nic_info()

        # Update each port's configuration
        for port in self.port_list:
            port_name = port.Interface

            # Update NIC information
            self._update_nic_info(port, port_name, nic_infos_ret["Data"]["PortArray"])

            # Update core binding information
            self._update_core_binding(port, port_name, port_info_ret["Data"]["TrafficPorts"])

            # Update send and receive queue information
            self._update_tx_rx_info(port)

    def _get_port_and_nic_info(self):
        """
        * Get port and NIC information
        """
        port_info_ret = self.client.get("/api/system/ports/show")
        if port_info_ret.get("ErrorCode") != 0:
            msg = f"get port info failed: {port_info_ret.get('ErrorMessage')}"
            logger.error(msg)
            raise Exception(msg)
        if "Data" not in port_info_ret or not port_info_ret["Data"]:
            msg = f"get port info Data failed"
            logger.error(msg)
            raise Exception(msg)

        nic_infos_ret = self.client.get("/api/system/netnic/infos")
        if nic_infos_ret.get("ErrorCode") != 0:
            msg = f"get nic info failed: {nic_infos_ret.get('ErrorMessage')}"
            logger.error(msg)
            raise Exception(msg)

        if "Data" not in nic_infos_ret or not nic_infos_ret["Data"]:
            msg = f"get nic info Data failed"
            logger.error(msg)
            raise Exception(msg)

        return port_info_ret, nic_infos_ret

    def _update_nic_info(self, port, port_name: str, nic_infos_list: list):
        """
        * Update NIC information
        """
        for nic_info in nic_infos_list:
            if nic_info["name"] == port_name:
                name_info = nic_info["name_info"]
                port.device = name_info["device"]
                port.driver = name_info["driver"]
                port.sendqueue = name_info["combined"]
                port.receivequeue = name_info["combined"]
                port.nictype = name_info["nictype"]
                break

    def _update_core_binding(self, port, port_name: str, traffic_port_list: list):
        """
        * Update core binding information
        """
        for traffic_port in traffic_port_list:
            if traffic_port["name"] == port_name:
                if self.test_type.startswith("RFC"):
                    port.CoreBind = traffic_port["rfc_cores"]
                else:
                    port.CoreBind = traffic_port["port_cores"]
                break

    def _update_tx_rx_info(self, port):
        """
        * Update send and receive queue information
        """
        tx_rx_dict = self.client.get("/api/ports/driver",
                                     {"Driver": port.driver, "Type": self.test_type})
        if tx_rx_dict.get("ErrorCode") != 0:
            msg = f"get tx rx info failed: {tx_rx_dict.get('ErrorMessage')}"
            logger.error(msg)
            raise Exception(msg)

        if "Data" not in tx_rx_dict or not tx_rx_dict["Data"]:
            msg = f"get tx rx info Data failed"
            logger.error(msg)
            raise Exception(msg)

        tx_rx_info = tx_rx_dict["Data"]
        port.nb_txd = tx_rx_info["nb_txd"]
        port.nb_rxd = tx_rx_info["nb_rxd"]

    def _get_advanced_fuzzing_running_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "selectedTabs": [],
            "ReportID": report_id,
            "TestType": "AdvancedFuzzing"
        }
        return self.client.post("/api/running/data/AdvancedFuzzing", payload)

    def _get_scenario_descrption_language_running_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "selectedTabs": [],
            "ReportID": report_id,
            "TestType": "ScenarioDescrptionLanguage"
        }
        return self.client.post("/api/running/data/ScenarioDescrptionLanguage", payload)

    def _get_layer7_running_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "selectedTabs": ["Status"],
            "LayerTabs": ["sum"],
            "ReportID": report_id,
            "TestType": self.test_type
        }

        return self.client.post("/api/running/data", payload)

    def _get_layer2_running_data(self, report_id, test_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        if not test_id:
            print("test_id can not be empty.")
            raise ValueError("test_id can not be empty.")

        payload = {
            "selectedTabs": ["Status"],
            "LayerTabs": ["sum"],
            "ReportID": report_id,
            "TestType": self.test_type,
            "Layer": "layer2"
        }

        return self.client.post("/api/running/get/layer2", payload)

    def _get_layer3_running_data(self, report_id, test_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        if not test_id:
            print("test_id can not be empty.")
            raise ValueError("test_id can not be empty.")

        payload = {
            "selectedTabs": ["Status"],
            "LayerTabs": ["sum"],
            "ReportID": report_id,
            "TestType": self.test_type,
            "Layer": "layer3"
        }

        return self.client.post("/api/running/get/layer3", payload)

    def _get_layer4_running_data(self, report_id, test_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        if not test_id:
            print("test_id can not be empty.")
            raise ValueError("test_id can not be empty.")

        payload = {
            "LayerTabs": ["sum"],
            "ReportID": report_id,
            "TestType": self.test_type,
            "Layer": "layer4",
            "WorkMode": "Standalone",
            "selectedTabs": ["layer4", "app", "sum"]
        }

        return self.client.post("/api/running/get/layer4", payload)

    def _get_key_result_running_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "ReportID": report_id,
            "type": "keyResult"
        }

        return self.client.get("/api/running/get/key_result", payload)

    def _get_system_resource_running_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "ReportID": report_id,
            "type": "systemResource"
        }

        return self.client.get("/api/running/get/system_resource", payload)

    def _get_capture_running_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "ReportID": report_id,
            "type": "capture"
        }

        return self.client.get("/api/running/get/capture", payload)

    def _get_descrption_report_paging_result_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "offset": 0,
            "size": 1000,
            "ReportID": report_id,
            "TestType": self.test_type
        }

        return self.client.get("/api/descrption_report/paging_result", payload)

    def _get_descrption_report_number_paging_result_data(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        payload = {
            "ReportID": report_id,
            "TestType": self.test_type
        }

        return self.client.get("/api/descrption_report_number/paging_result", payload)

    def _get_fuzzing_sqlite_statistics(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        params = {
            "offset": 0,
            "size": 1000,
            "reportId": report_id,
        }

        return self.client.get("/api/history/fuzzing/sqlite_statistics", params)

    def _get_fuzzing_sqlite_result(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        params = {
            "offset": 0,
            "size": 1000,
            "reportId": report_id,
        }

        return self.client.get("/api/history/fuzzing/sqlite_result", params)

    def _fuzzing_sqlite_parser(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        params = {
            "historyID": report_id
        }

        return self.client.get("/api/history/fuzzing/sqlite_parser", params)

    def _fuzzing_progress(self, report_id):

        if not report_id:
            print("report_id can not be empty.")
            raise ValueError("report_id can not be empty.")

        params = {
            "historyID": report_id
        }

        return self.client.get("/api/history/fuzzing/progress", params)

    def ConfigNetworkIpAddress(self, port_name: str, ip_address: str):
        """
        * Configure IP address for a port
        """
        self.Config("NetworkSubnet", {port_name: {"SubnetNumber": 1, "IpAddrRange": ip_address}})

    def ConfigNetworkNetmask(self, port_name: str, netmask: str):
        """
        * Configure netmask for a port
        """
        self.Config("NetworkSubnet", {port_name: {"SubnetNumber": 1, "Netmask": netmask}})

    def ConfigNetworkGateway(self, port_name: str, gateway: str):
        """
        * Configure gateway for a port
        """
        self.Config("NetworkSubnet", {port_name: {"SubnetNumber": 1, "Gateway": gateway}})

    def ConfigNetworkServerIP(self, port_name: str, server_ip: str):
        """
        * Configure gateway for a port
        """
        self.Config("NetworkSubnet", {port_name: {"SubnetNumber": 1, "ServerIPRange": server_ip}})

    def ConfigInterfaceCpuList(self, port_name: str, cpu_list_str: str):
        """
        * Configure CPU list for a port
        """
        self.Config("InterfaceCPU", f"{port_name}:{cpu_list_str}")

    def Getresult(self):
        if self.test_type in ["ScenarioDescrptionLanguage"]:
            res = self._get_descrption_report_number_paging_result_data(self.report_id)
            print(res)
        elif self.test_type in ["AdvancedFuzzing"]:
            res = self._get_fuzzing_sqlite_statistics(self.report_id)
            if res.get("ErrorCode") == 0:
                data = res.get("Data", {})
                result_json = {
                    "Execution_passed": data.get("pass", None),
                    "error": data.get("error", None),
                    "Reconnection_num": data.get("restart", None),
                    "total": data.get("total", None),
                    "icmp_avg_latency": data.get("fuzzing_avg", None),
                    "fuzzing_min": data.get("fuzzing_min", None),
                    "fuzzing_max": data.get("fuzzing_max", None),
                    "icmp_timeout_num": data.get("timeout_num", None)
                }

                print(result_json)
            else:
                print("get result error", res)
        else:
            res = self._get_layer2_running_data(self.report_id, self.case_id)

            if res.get("ErrorCode") == 0:
                print(res.get("Data"))
            else:
                print("get result error", res)

    def DownLoadLogFile(self, filepath="./"):
        print("download log file start")
        if self.test_type == "AdvancedFuzzing":
            params = {
                "reportID": self.report_id,
                "testType": self.test_type,
                "logFile": "fuzzing_log"
            }
            self.client.download_file("/api/case/logfile/down_file", params, filepath)

        print(f"download log file end, filepath: {filepath}")

    def Monitor(self):
        while True:
            status_ret = self.client.get("/api/running/status")
            running_status = status_ret['Data']["TestStatus"] if status_ret else ""
            report_id = status_ret['Data']["ReportID"] if status_ret else ""
            test_type = self.test_type
            if running_status == "Running":
                self.report_id = report_id
                if test_type == "AdvancedFuzzing":

                    res = self._get_advanced_fuzzing_running_data(report_id)
                    if res.get("ErrorCode") == 0:
                        detail = res.get("Data", {}).get("Detail")
                        if detail:
                            session_info = detail.get("session_info", {})
                            print({
                                "crashes": session_info.get("crashes", []),
                                "current_element": session_info.get("current_element", ""),
                                "current_index": session_info.get("current_index", ""),
                                "current_test_case_name": session_info.get("current_test_case_name", ""),
                                "exec_speed": session_info.get("exec_speed", ""),
                                "runtime": round(session_info.get("runtime", 0), 2)
                            })
                        else:
                            print({})
                    else:
                        print("get advanced fuzzing data error", res)

                elif test_type == "ScenarioDescrptionLanguage":
                    # res = self._get_scenario_descrption_language_running_data(report_id)
                    # if res.get("ErrorCode") == 0:
                    #     print(res.get("Data", {}).get("Detail"))
                    # else:
                    #     print("get scenario descrption language data error", res)

                    res = self._get_descrption_report_number_paging_result_data(self.report_id)
                    print(res)
                else:
                    res = self._get_layer2_running_data(report_id, self.case_id)

                    if res.get("ErrorCode") == 0:
                        print(res.get("Detail"))
                    else:
                        print("get layer2 error", res)

            if running_status == "Stopping":
                print("Test case is stopping!")

            if running_status == "Stopped":
                print("Test case has stopped!, running result: " + status_ret['Data']['ErrorMessage'])
                break

            time.sleep(1)

        print("Test program ended!")
        return 'Test program ended!'

    def AnalysisResult(self):

        res_parse = self._fuzzing_sqlite_parser(self.report_id)

        if res_parse.get("ErrorCode") == 0:
            print("Test case start analysis result successful")
        else:
            print("Test case start analysis result failed", res_parse)
            return res_parse

        while True:
            res = self._fuzzing_progress(self.report_id)
            data = res.get("Data")
            running_status = data["Status"] if res else ""
            if running_status == "Running":
                if res.get("ErrorCode") == 0:
                    print(data)
                else:
                    print("get analysis result error", res)

            if running_status == "Stopping":
                print("Test analysis result is stopping!")

            if running_status == "Stopped":
                print("Test case analysis has stopped!, analysis result: ", data)
                time.sleep(2)
                break

            time.sleep(1)

        print("Test program analysis ended!")
        return 'Test program analysis ended!'

    def CustomMonitorOutput(self):

        output_dict = {
            "HttpRequestFlood": {
                "layer7": ["n70558_Add_Send_Get_Flood", "n70559_Add_Recv_Get_Flood", "n70561_Avg_Http_Rep_Suc_Rate"]
            }
        }

        while True:
            status_ret = self.client.get("/api/running/status")
            running_status = status_ret['Data']["TestStatus"] if status_ret else ""
            report_id = status_ret['Data']["ReportID"] if status_ret else ""
            test_id = status_ret['Data']["TestID"] if status_ret else ""

            test_type = self.test_type
            custom_dict = output_dict.get(test_type)
            output_msg = {}
            if not custom_dict:
                if running_status == "Running":
                    self.report_id = report_id
                    print("Not set custom monitor output")
                    time.sleep(1)

            else:
                if running_status == "Running":
                    self.report_id = report_id
                    for datatype, data_list in custom_dict.items():
                        if datatype == "layer7":
                            res = self._get_layer7_running_data(report_id)
                            if res.get("ErrorCode") == 0:
                                detail = res.get("Detail")
                            else:
                                detail = None
                            if not detail:
                                continue
                            app = detail.get("app")
                            for data_key in data_list:
                                output_msg[data_key] = app.get(data_key)

                    print(f"{test_type}: {output_msg}")
                    time.sleep(1)

            if running_status == "Stopping":
                print("Test case is stopping!")

            if running_status == "Stopped":
                print("Test case has stopped!")
                break

            time.sleep(1)

        print("Test program ended!")
        return 'Test program ended!'

    def TestedResult(self):
        while True:
            ret = {}
            status_ret = self.client.get("/api/running/status")
            running_status = status_ret['Data']["TestStatus"] if status_ret else ""
            report_id = status_ret['Data']["ReportID"] if status_ret else ""
            if running_status == "Running":
                self.report_id = report_id

                print('case running...')
            test_status = status_ret['Data']["ErrorCode"]
            if test_status == 0:
                test_status = 'Success'
            else:
                test_status = 'Fail'
            if running_status == "Stopping":
                print('case stoping...')
                ret[status_ret['Data']['TestName']] = test_status
            if running_status == "Stopped":
                print('case stopped...')
                ret[status_ret['Data']['TestName']] = test_status
                # ret = status_ret['Data']["ErrorMessage"]
                break
            time.sleep(1)

        execute_ret = self.client.get(f"/api/history/profile/{report_id}")
        error_code = execute_ret['Data']["ErrorCode"]

        if error_code == 0:
            ret["ExecuteResult"] = "成功"
        elif error_code == 1:
            ret["ExecuteResult"] = "用户中断"
        else:
            ret["ExecuteResult"] = "失败"

        logger.info(f"TestedResult: {ret}")
        return ret

    def GenerateReport(self):
        self.client.get(f"/api/history/report/{self.report_id}/start")
        time.sleep(1)
        while True:
            res = self.client.get(f"/api/history/report/{self.report_id}/monitor")
            time.sleep(1)
            if res.get("ErrorCode") == 0:
                summary_progress = res.get("ReportProgress").get('summary').get('progress')
                print(f"Summary progress: {summary_progress}")
                if summary_progress == 100:
                    break
            else:
                print("get report monitor error", res)
                break
        return 'generte report end'

    def DownLoadReport(self, down_file_type, filepath="./"):
        # generate document
        self.client.get(f"/api/history/pdf/{self.report_id}/start", {"reportTypes": "html,pdf,word,excel"})
        time.sleep(1)
        while True:
            # monitor progress
            res = self.client.get(f"/api/history/report/{self.report_id}/monitor")
            time.sleep(1)
            if res.get("ErrorCode") == 0:
                html_summary_progress = res.get("ReportProgress").get('html').get('progress')
                pdf_summary_progress = res.get("ReportProgress").get('pdf').get('progress')
                word_summary_progress = res.get("ReportProgress").get('word').get('progress')
                excel_summary_progress = res.get("ReportProgress").get('excel').get('progress')
                print(f"html_summary_progress: {html_summary_progress}", f"pdf_summary_progress: {pdf_summary_progress}",
                      f"word_summary_progress: {word_summary_progress}", f"excel_summary_progress: {excel_summary_progress}")
                if (html_summary_progress == 100) and (pdf_summary_progress == 100) and (word_summary_progress == 100) and (excel_summary_progress == 100):
                    break
            else:
                print("get report monitor error", res)
                break
        # download document
        if "html" in down_file_type:
            self.client.download_file(f"/api/history/down_html", {"historyId": self.report_id}, filepath)
        if "pdf" in down_file_type:
            self.client.download_file(f"/api/history/down_pdf", {"historyId": self.report_id}, filepath)
        if "word" in down_file_type:
            self.client.download_file(f"/api/history/down_word", {"historyId": self.report_id}, filepath)
        if "excel" in down_file_type:
            self.client.download_file(f"/api/history/down_excel", {"historyId": self.report_id}, filepath)
        return 'download report end'

    def GetSummary(self):
        # http://192.168.15.100/api/history/report/{rptid}/start
        payload = {"selectedTabs": ["Status"], "reportId": self.report_id, "testType": self.test_type}
        res = self.client.post("/api/history/by_tab", payload)
        if res.get("ErrorCode") == 0:
            # English to Chinese
            if self.test_type == "Rfc2544Throughput":
                port_list = res.get("Data", {}).get("Port", [])
                for port_dict in port_list:
                    port_data_list = port_dict.get("data")
                    for port_data in port_data_list:
                        chinese_dict_list = []
                        result_data_list = port_data.get("data")
                        for result_data in result_data_list:
                            result_data["Lose_Rate_Passed"] = "成功" if result_data["Lose_Rate_Passed"] == 1 else "失败"
                            # key change chinese
                            chinese_dict = {
                                EnglishChineseDict.get(k, k): v
                                for k, v in result_data.items()
                            }
                            chinese_dict_list.append(chinese_dict)
                        port_data["data"] = chinese_dict_list

            print('Summary:', res.get("Data"))
            return res.get("Data")
        else:
            print("get summary error", res)
            return None

    def GetResultView(self):
        payload = {
            "selectedTabs": ["ResultView"],
            "reportId": self.report_id,
            "testType": self.test_type
        }

        res = self.client.post("/api/history/result_view", payload)
        if res.get("ErrorCode") == 0:
            self.case_id = res.get("Data")
            print('get result view successfully', res)
        else:
            print("get result view failed!  Errormsg:" + res.get("ErrorMessage"))
        time.sleep(1)

    def GetFuzzingObjectCaseList(self, case_config):

        payload = {
            "dutRole": case_config.get("dutRole", "Gateway"),
            "Role": self.client.encrpt_role,
            "User": self.client.encrpt_name
        }

        res = self.client.get("/api/case/fuzzing", payload)
        if res.get("ErrorCode") == 0:
            print(res.get("payload"))
        else:
            print("Use case creation failed, Errormsg:" + res.get("ErrorMessage"))
        time.sleep(1)

    def Apply(self, case_config):
        res = self.client.post("/api/case", case_config)
        if res.get("ErrorCode") == 0:
            self.case_id = res.get("Data")
            print('Use case created successfully', res)
        else:
            print("Use case creation failed, Errormsg:" + res.get("ErrorMessage"))
        time.sleep(1)

    def Start(self):
        res = self.client.get(f"/api/case/{self.case_id}/start")

        if res.get("ErrorCode") == 0:
            print("Test case startup successful")
        else:
            print("Test case startup failed", res)

    def ModifyStreamConfig(self, payload: dict = None):

        # get report id
        status_ret = self.client.get("/api/running/status")
        report_id = status_ret['Data']["ReportID"] if status_ret else ""

        # have data, then start streaming
        while True:
            res = self._get_layer7_running_data(report_id)
            if res.get("ErrorCode") == 0:
                detail = res.get("Data", {}).get("Detail")
                if detail:
                    break
            else:
                print("get layer7 running data failed", res)

        if not payload:
            payload = {
                "Action": "Send_Udp",
                "IP_Version": "V4",
                "PortName": "all_client",
                "rt_strm_dst_port": "6000/0",
                "rt_strm_dst_port_mode": "single",
                "rt_strm_mode": "to_one",
                "rt_strm_src": "Emu",
                "rt_strm_src_port": "10000/0",
                "rt_strm_src_port_mode": "single",
                "rt_strm_target": "peer_port_sim",
                "strm_appoint_ip": "17.1.1.3+10/0.0.1.0",
                "strm_dst_ip": "65.1.1.3+10/0.0.1.0"
            }

        payload["ReportID"] = report_id

        res = self.client.post(f"/api/stream_config/modify", payload)

        if res.get("ErrorCode") == 0:
            print(res.get("ErrorMessage"))
        else:
            print("modify stream config failed, ErrorMessage: ", res.get("ErrorMessage"))

    def GetCaseListByName(self, test_type):
        menu_mode_dict = {
            "Layer47Test": ["HttpCps", "HttpForceCps", "HttpCc", "HttpThroughput", "HttpsCps", "HttpsCc", "HttpsThroughput", "SSLHandshake"],
            "Layer23Test": ["Rfc2544Throughput", "Rfc2544Latency", "Rfc2544LossRate", "Rfc2544BackToBack"],
            "NetworkSecurityTest": ["VulnerabilityScanner", "WebScanner", "NetworkDiscovery", "Ipv4FragAttack", "ICMPSinglePacketAttack", "IGMPv4SinglePacketAttack",
                                    "ARPv4SinglePacketAttack", "TCPSinglePacketAttack", "UDPSinglePacketAttack", "UDPPayloadAttack", "SipSinglePacketAttack", "DnsServiceAttack",
                                    "DnsAmplificationAttack", "SSDPAttack", "NtpAmplificationAttack", "MemcachedAmplificationAttack", "UnknownProtocolSinglePacketAttack",
                                    "HttpRequestFlood", "HttpsFlood", "HTTPSlowRequestFlood", "MultiTypeFlood", "TcpSessionFlood", "TCPWinnuke", "HttpMultipleRequest",
                                    "HttpRecursionRequest", "HttpConcurrentSlowRead", "HttpConcurrentSlowRequest", "UnicastStorm", "BroadcastStorm", "MulticastStorm"
                                    "SVStormTest", "GooseStormTest", "MmsConnectStorm", "LLDPStormTest"],
            "PrivateNetworkTest": [],
            "TestAnalysisTools": [],
            "TrafficGeneratorTools": []
        }

        search_menu_mode = "Layer47Test"

        for menu_mode, test_type_list in menu_mode_dict.items():
            if test_type in test_type_list:
                search_menu_mode = menu_mode
                break

        params = {
            "offset": 0,
            "size": 1000,
            "testType": test_type,
            "DUTRole": "all",
            "MenuMode": search_menu_mode,
            "User": "admin",
            "Role": "admin"
        }
        res = self.client.get(f"/api/case/test_type", params)
        return res

    def StartExistExample(self, case_name):
        case_id = None
        ret = self.GetCaseListByName(self.test_type)
        case_list = ret.get("payload")
        if not case_list:
            msg = f"There is no such instance, testtype: {self.test_type}"
            raise ValueError(msg)

        for case in case_list:
            test_name = case.get("TestName")
            if test_name == case_name:
                case_id = case.get("_id")

        if not case_id:
            msg = f"There is no such instance, testtype: {self.test_type}, case_name: {case_name}"
            raise ValueError(msg)

        res = self.client.get(f"/api/case/{case_id}/start")

        if res.get("ErrorCode") == 0:
            print("Test case startup successful")
        else:
            print("Test case startup failed", res)

    def Config(self, key, *args):
        handler_map = {
            "Interface": self._handle_interface,
            "InterfaceCPU": self._handle_interface_cpu,
            "NetworkSubnet": self._handle_network_subnet,
            "UserApplyMemoryMB": self._handle_user_apply_memory,
            "DPDKHugeMemoryPct": self._handle_huge_page_memory,
            "CaseAssignMemoryGB": self._handle_case_assign_memory_gb,
            "TestName": self._handle_test_name,
            "TestDuration": self._handle_test_duration,
            "CaseObject": self._handle_case_object,
            "SimUser": self._handle_sim_user,
            "Latency": self._handle_latency,
            "DualFlowMode": self._handle_dual_flow_mode,
            "FrameSizePolicy": self._handle_frame_size_policy,
            "CycleDurationPolicy": self._handle_cycle_duration_policy,
            "PortLimitValue": self._handle_port_limit_value,
            "LoadLimitPolicy": self._handle_load_limit_policy,
            "Fuzzing": self._handle_fuzzing,
            "IndexStart": self._handle_index_start,
            "IndexEnd": self._handle_index_end,
            "FuzzDbKeepOnlyNPassCases": self._handle_fuzz_db_keep_only_n_pass_cases,
            "ReuseTargetConnection": self._handle_reuse_target_connection,
            "ServerPort": self._handle_server_port,
            "TestMode": self._handle_test_mode,
            "NetworkZone": self._handle_network_zone,
            "VirtualRouterConfig": self._handle_virtual_router_config,
            "AdditionalFields": self._handle_additional_fields,

            "Descrption": self._handle_descrption,
            "App_scenario": self._handle_app_scenario,
            "Malware": self._handle_malware,
            "Mitre": self._handle_mitre,

            "SendWaitTime": self._handle_send_wait_time,
            "SendNumCyles": self._handle_send_num_cyles,
            "ScenarioTimeout": self._handle_scenario_timeout,
            "ScenarioInterval": self._handle_scenario_interval,
            "SockRecvTimeout": self._handle_sock_recv_timeout,
            "MaximumIterativeCycle": self._handle_maximum_iterative_cycle,

        }

        handler = handler_map.get(key)
        if handler:
            return handler(*args)
        msg = f"Unsupported config key: {key}"
        logger.error(msg)
        raise ValueError(msg)

    def _handle_interface(self, *args):
        dut_role = self.case_config.get("DUTRole")
        # 1. Parse the passed parameters
        client_ports = []
        server_ports = []
        if dut_role in ["Gateway", "Proxy"]:
            client_ports = self.parse_port_list(args[0])
            server_ports = self.parse_port_list(args[1])
        elif dut_role == "Server":
            client_ports = self.parse_port_list(args[0])
        elif dut_role == "Client":
            server_ports = self.parse_port_list(args[0])

        # 2. Add network port configuration
        port_subnet_list = []
        if client_ports:
            logger.info(f"Adding client interface: {client_ports} in the test case")
        for port_name in client_ports:
            # Client port
            real_port_name = port_name.strip()
            if real_port_name:
                self._add_port_config(real_port_name, 'client', port_subnet_list)
        if server_ports:
            logger.info(f"Adding server interface: {server_ports} in the test case")
        for port_name in server_ports:
            # Server port
            real_port_name = port_name.strip()
            if real_port_name:
                self._add_port_config(port_name, 'server', port_subnet_list)

        self.case_config["NetworkConfig"]["SlaveHost"][0]["Ports"] = port_subnet_list

        if ToolsUtils.is_dpdk_test_type(self.test_type):
            self.update_port_default_values()

    def _handle_interface_by_json(self, config_json):

        port_subnet_list = []
        port_json_list = config_json["NetworkConfig"]["SlaveHost"][0]["Ports"]

        for port_json in port_json_list:
            port_name = port_json["Interface"]
            port_side = port_json["PortSide"]
            port_config = CustomPortConfig(port_name, port_side, port_json, config_json)
            self.port_list.append(port_config)
            port_subnet_list.append(port_config.to_dict())

        self.case_config["NetworkConfig"]["SlaveHost"][0]["Ports"] = port_subnet_list

    def _add_port_config(self, port_name: str, port_side: str, port_list: list):
        port_config = PortConfig(port_name, port_side, self.case_config)
        self.port_list.append(port_config)
        port_list.append(port_config.to_dict())

    def _handle_interface_cpu(self, *args):
        if self.test_type not in ["AdvancedFuzzing"]:
            logger.info("Handling CPU core bind config")
            for port_core_str in args:
                port_name, core_list_str = self._parse_core_str(port_core_str)
                self._apply_core_binding(port_name, core_list_str)
                logger.info(f"Port {port_name} bound to CPU cores: {core_list_str}")

    def _parse_core_str(self, port_core_str: str):
        parts = port_core_str.split(':', 1)
        return parts[0], parts[1].strip()

    def _apply_core_binding(self, port_name: str, core_list_str: str):
        # set core binding
        for port in self.port_list:
            if port.Interface == port_name:
                # check cpu core range
                core_numbers = [int(core.strip()) for core in core_list_str.split(',')]
                port_info_ret = self.client.get(f"/api/system/ports/show")
                if port_info_ret.get("ErrorCode") != 0:
                    msg = f"get port info failed: {port_info_ret.get('ErrorMessage')}"
                    logger.error(msg)
                    raise Exception(msg)

                if "Data" not in port_info_ret or "TrafficCpus" not in port_info_ret["Data"]:
                    msg = f"get port info Data failed"
                    logger.error(msg)
                    raise Exception(msg)

                traffic_cpu_dict = port_info_ret["Data"]["TrafficCpus"]
                available_cores = set()
                for cpu_dict in traffic_cpu_dict.values():
                    cpu_cores = cpu_dict["cores"]
                    # check whether the core binding is in available range
                    available_cores.update(set(int(core) for core in cpu_cores.split(',')))
                invalid_cores = set(core_numbers) - available_cores
                if invalid_cores:
                    msg = f"CPU core: {invalid_cores} is out of available range: {available_cores}"
                    logger.error(msg)
                    raise ValueError(msg)

                port.set_port_core_bind(core_list_str)

    def _handle_network_subnet(self, *args):
        logger = LoggerUtils.get_logger()
        logger.info("Start modifying the subnet configuration.")
        try:
            dut_role = self.case_config.get("DUTRole")
            proxy_mode = self.case_config.get("ProxyMode")
            BaseSubnet.config_subnet_parameters(args, self.port_list, dut_role, proxy_mode)
        except Exception as e:
            logger.error(str(repr(e)))
            sys.exit()

    def _handle_network_zone(self, *args):
        logger = LoggerUtils.get_logger()
        logger.info("Start modifying the zone configuration.")
        try:
            NetworkZoneDict.config_zone_parameters(args, self.port_list)
        except Exception as e:
            logger.error(str(repr(e)))
            sys.exit()

    def _handle_virtual_router_config(self, *args):
        logger = LoggerUtils.get_logger()
        logger.info("Start modifying the zone configuration.")
        try:
            VirtualRouterConfigDict.config_virtual_router_parameters(args, self.port_list)
        except Exception as e:
            logger.error(str(repr(e)))
            sys.exit()

    def _handle_additional_fields(self, *args):
        logger = LoggerUtils.get_logger()
        logger.info("Start modifying the additional fields configuration.")
        try:
            AdditionalFields.config_additional_fields_parameters(args, self.port_list)
        except Exception as e:
            logger.error(str(repr(e)))
            sys.exit()

    def write_json_to_file(self, json_data: dict, filepath: str = "./"):
        """
        Write the incoming dictionary data to the JSON file

        :param json_data: The dictionary object to be written to
        :param filepath: file save path
        """
        filename = f"{self.test_type}-config.json"
        full_path = os.path.join(filepath, filename)
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=4, ensure_ascii=False)

        print(f"JSON 数据已写入文件: {full_path}")

    def ReplaceDefaultValue(self, json_data):

        # replace Base value
        if json_data["TestName"]:
            self.case_object.base.set_test_name(json_data["TestName"])

        if json_data.get("TestMode"):
            self.case_object.base.set_test_mode(json_data["TestMode"])

        if json_data.get("DUTRole"):
            self.case_object.base.set_dut_role(json_data["DUTRole"])

        if json_data.get("ProxyMode"):
            self.case_object.base.set_proxy_mode(json_data["ProxyMode"])

        if json_data.get("TestDuration"):
            self.case_object.base.set_test_duration(json_data["TestDuration"])

        if json_data.get("WorkMode"):
            self.case_object.base.set_work_mode(json_data["WorkMode"])

        # replace Specifics value
        self.case_object.case_model.Loads.__dict__.update(json_data["Specifics"][0]["Loads"])
        self.case_object.case_model.CaseObject.__dict__.update(json_data["Specifics"][0]["CaseObject"])
        self.case_object.case_model.ClientProfiles.__dict__.update(json_data["Specifics"][0]["ClientProfiles"])
        self.case_object.case_model.ServerProfiles.__dict__.update(json_data["Specifics"][0]["ServerProfiles"])

        # replace NetworkConfig value
        self._handle_interface_by_json(json_data)

    def WriteJsonToFile(self, json_data: dict, filepath: str = "./"):
        self.write_json_to_file(json_data, filepath)


class TestFactory:
    @staticmethod
    def create(test_type, dut_role):
        if not test_type:
            raise ValueError("test_type must not be empty")
        if not dut_role:
            raise ValueError("dut_role must not be empty")

        return GenericTestCaseModel(test_type=test_type, dut_role=dut_role)


class CreateProject:
    def __init__(self):
        self.host = ''
        self.host_port = 80
        self.client = None

    def delete_case(self, test_type='', test_name_list=[]):
        """ Import Use Case

        Args:
            test_name_list (list): case test_name list
            test_type (str): user case type
        """
        if (not test_type) or (not test_name_list):
            print("test_type and test_name_list can not be empty")
            raise ValueError("test_type and test_name_list can not be empty")

        payload = {
            "testNames": test_name_list,
            "testType": test_type
        }
        logger.info("Start delete cases")
        self.client.post("/api/case/delete", payload)
        logger.info("delete cases was successful.")

    def import_case(self, file_name, test_type=''):
        """ Import Use Case

        Args:
            file_name (str): local file path
            test_type (str): user case type
        """
        logger.info("Start importing use cases")
        error_code, error_message = self.client.import_file("/api/case/import", file_name, test_type)
        logger.info("Import of the use case was end.")
        return error_code, error_message

    def export_case(self, test_name):
        """ Export Use Case

        Args:
            test_name: use-case name
        """
        logger.info("Start exporting use cases")
        self.client.download_file("/api/case/export", {"testName": test_name, "DisplayName": test_name})
        logger.info("Export of use cases was successful.")

    def _check_packet(self, report_id: str) -> str:
        """Validate packet file availability"""
        response = self.client.get(
            "/api/history/check_packet",
            params={"historyId": report_id}
        )
        if response.get("ErrorCode") != 0:
            logger.error("Packet check failed. Code: %s, Message: %s",
                         response.get("ErrorCode"),
                         response.get("ErrorMessage", "Unknown error"))
            raise Exception("Packet file not available")
        return response.get("ErrorMessage", "")

    def DownloadHistoryPcap(self, test_name: str, start_time: str = "", save_dir: str = "") -> str:
        """
        Download historical packet capture files with enhanced error handling

        Args:
            test_name (str): Test case name (required)
            start_time (str, optional): Start time filter in ISO 8601 format
            save_dir (str, optional): Custom save directory. Defaults to current directory

        Returns:
            str: Full path to downloaded packet file

        Raises:
            ValueError: If required parameters are missing
            requests.exceptions.RequestException: For network errors
            IOError: For file write errors
        """
        if not test_name:
            raise ValueError("Test name cannot be empty")

        logger.info(f"Starting packet capture download for test: {test_name}")
        try:
            # 1. Get report ID
            query = {"TestName": test_name}
            if start_time:
                query["StartTime"] = start_time
            report_id = self._get_report_id(query)

            # 2. Validate packet availability
            packet_path = self._check_packet(report_id)

            # 3. Prepare file path
            file_name = f'packet_capture_{report_id}.tar.gz'
            save_path = os.path.abspath(os.path.join(save_dir or os.getcwd(), file_name))

            # 4. Download file
            self.client.get_download(
                "/api/history/down_packet",
                params={"Path": packet_path},
                file_path=save_path
            )
            return save_path

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {str(e)}")
            raise
        except IOError as e:
            logger.error(f"File write error: {str(e)}")
            raise
        except Exception as e:
            logger.exception("Unexpected error in packet download")
            raise

    def _check_testerlog(self, report_id):
        """Helper method to validate log availability"""
        response = self.client.get(
            "/api/history/check_testerlog",
            params={"historyId": report_id}
        )
        if response.get("ErrorCode") != 0:
            logger.error("Log check failed. Response: %s", response)
            raise Exception(f"Log validation failed: {response.get('ErrorMessage', 'Unknown error')}")
        return response.get("ErrorMessage", "")

    def _get_report_id(self, query: dict) -> str:
        """Get report ID from API"""
        response = self.client.post("/api/history/get_report_id", query)
        if response.get("ErrorCode") != 0:
            logger.error("Report ID request failed. Code: %s, Message: %s",
                         response.get("ErrorCode"),
                         response.get("ErrorMessage", "Unknown error"))
            raise Exception("Failed to get report ID")
        return response.get("Data", {}).get("ReportID", "")

    def DownloadHistoryTesterLog(self, test_name, start_time=None, save_dir=None):
        """Download historical tester logs with enhanced error handling and progress tracking

        Args:
            test_name (str): Name of the test case
            start_time (str, optional): Start time filter in ISO format
            save_dir (str, optional): Directory to save logs. Defaults to current directory

        Returns:
            str: Path to downloaded log file

        Raises:
            Exception: If any API request fails or file write fails
        """
        logger.info(f"Starting historical log download for test: {test_name}")
        try:
            # 1. Get report ID
            query = {"TestName": test_name}
            if start_time:
                query["StartTime"] = start_time

            report_id = self._get_report_id(query)

            # 2. Validate log availability
            log_path = self._check_testerlog(report_id)

            # 3. Download log file
            file_name = f'testerlog_{report_id}.tgz'
            save_path = os.path.join(save_dir or os.getcwd(), file_name)

            self.client.get_download(
                "/api/history/down_testerlog",
                params={"Path": log_path},
                file_path=save_path
            )
            return save_path

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during download: {str(e)}")
            raise
        except IOError as e:
            logger.error(f"File write error: {str(e)}")
            raise
        except Exception as e:
            logger.exception("Unexpected error during log download")
            raise

    def is_accessible(self):
        if not NetworkUtils.ping_host(self.host):
            print(f"Host {self.host} network unreachable")
            return False
        if not NetworkUtils.check_port(self.host, self.host_port):
            print(f"Port {self.host_port} unreachable")
            return False
        return True

    def Connect(self, host, port):
        self.host = host
        self.host_port = port

        base_url = f"http://{self.host}:{self.host_port}"

        if not self.is_accessible():
            logger.error(f"Connection to {base_url} failed")
            sys.exit()

        base_url = f"http://{self.host}:{self.host_port}"
        self.client = HttpClient(base_url)
        logger.info(f"Connected to {self.client.base_url}")

    def Login(self, username, password):
        if not self.is_accessible():
            return None

        payload = {
            "name": username,
            "password": password
        }
        self.client.login(payload)

    def CreateCase(self, test_type, dut_role, proxy_mode="Reverse"):
        logger.info(f"Start to create test case: {test_type}")
        try:
            case = TestCase(self.host, self.client, test_type, dut_role, proxy_mode)
        except Exception as e:
            logger.error("Create test case failed")
            sys.exit()
        else:
            logger.info(f"Create test case: {test_type} successfully")

        return case

    def ReadJsonByZip(self, zip_file_name):
        import zipfile

        if not os.path.exists(zip_file_name):
            print(f"zip_file_name: {zip_file_name} not exists")
            return None

        read_json_file = False

        with zipfile.ZipFile(zip_file_name, 'r') as zip_file:
            file_names = zip_file.namelist()
            print(f"zip_file_name: {zip_file_name}, file_names: {file_names}")

            for file_name in file_names:
                if file_name.endswith(".json"):
                    read_json_file = True
                    print(f"read json file: {file_name}")
                    with zip_file.open(file_name) as file:
                        content = file.read().decode('utf-8')
                        return content

        if not read_json_file:
            print("not read json file")
            return None

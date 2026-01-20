from __future__ import annotations

# Oh god oh why what did I do
# Is this better than a giant object.py? Who knows, we're rolling with it for now
from dissect.database.ese.ntds.objects.applicationsettings import ApplicationSettings
from dissect.database.ese.ntds.objects.attributeschema import AttributeSchema
from dissect.database.ese.ntds.objects.builtindomain import BuiltinDomain
from dissect.database.ese.ntds.objects.certificationauthority import CertificationAuthority
from dissect.database.ese.ntds.objects.classschema import ClassSchema
from dissect.database.ese.ntds.objects.classstore import ClassStore
from dissect.database.ese.ntds.objects.computer import Computer
from dissect.database.ese.ntds.objects.configuration import Configuration
from dissect.database.ese.ntds.objects.container import Container
from dissect.database.ese.ntds.objects.controlaccessright import ControlAccessRight
from dissect.database.ese.ntds.objects.crldistributionpoint import CRLDistributionPoint
from dissect.database.ese.ntds.objects.crossref import CrossRef
from dissect.database.ese.ntds.objects.crossrefcontainer import CrossRefContainer
from dissect.database.ese.ntds.objects.dfsconfiguration import DfsConfiguration
from dissect.database.ese.ntds.objects.displayspecifier import DisplaySpecifier
from dissect.database.ese.ntds.objects.dmd import DMD
from dissect.database.ese.ntds.objects.dnsnode import DnsNode
from dissect.database.ese.ntds.objects.dnszone import DnsZone
from dissect.database.ese.ntds.objects.domain import Domain
from dissect.database.ese.ntds.objects.domaindns import DomainDNS
from dissect.database.ese.ntds.objects.domainpolicy import DomainPolicy
from dissect.database.ese.ntds.objects.dsuisettings import DSUISettings
from dissect.database.ese.ntds.objects.filelinktracking import FileLinkTracking
from dissect.database.ese.ntds.objects.foreignsecurityprincipal import ForeignSecurityPrincipal
from dissect.database.ese.ntds.objects.group import Group
from dissect.database.ese.ntds.objects.grouppolicycontainer import GroupPolicyContainer
from dissect.database.ese.ntds.objects.infrastructureupdate import InfrastructureUpdate
from dissect.database.ese.ntds.objects.intersitetransport import InterSiteTransport
from dissect.database.ese.ntds.objects.intersitetransportcontainer import InterSiteTransportContainer
from dissect.database.ese.ntds.objects.ipsecbase import IpsecBase
from dissect.database.ese.ntds.objects.ipsecfilter import IpsecFilter
from dissect.database.ese.ntds.objects.ipsecisakmppolicy import IpsecISAKMPPolicy
from dissect.database.ese.ntds.objects.ipsecnegotiationpolicy import IpsecNegotiationPolicy
from dissect.database.ese.ntds.objects.ipsecnfa import IpsecNFA
from dissect.database.ese.ntds.objects.ipsecpolicy import IpsecPolicy
from dissect.database.ese.ntds.objects.leaf import Leaf
from dissect.database.ese.ntds.objects.linktrackobjectmovetable import LinkTrackObjectMoveTable
from dissect.database.ese.ntds.objects.linktrackvolumetable import LinkTrackVolumeTable
from dissect.database.ese.ntds.objects.locality import Locality
from dissect.database.ese.ntds.objects.lostandfound import LostAndFound
from dissect.database.ese.ntds.objects.msauthz_centralaccesspolicies import MSAuthzCentralAccessPolicies
from dissect.database.ese.ntds.objects.msauthz_centralaccessrules import MSAuthzCentralAccessRules
from dissect.database.ese.ntds.objects.msdfsr_content import MSDFSRContent
from dissect.database.ese.ntds.objects.msdfsr_contentset import MSDFSRContentSet
from dissect.database.ese.ntds.objects.msdfsr_globalsettings import MSDFSRGlobalSettings
from dissect.database.ese.ntds.objects.msdfsr_localsettings import MSDFSRLocalSettings
from dissect.database.ese.ntds.objects.msdfsr_member import MSDFSRMember
from dissect.database.ese.ntds.objects.msdfsr_replicationgroup import MSDFSRReplicationGroup
from dissect.database.ese.ntds.objects.msdfsr_subscriber import MSDFSRSubscriber
from dissect.database.ese.ntds.objects.msdfsr_subscription import MSDFSRSubscription
from dissect.database.ese.ntds.objects.msdfsr_topology import MSDFSRTopology
from dissect.database.ese.ntds.objects.msdns_serversettings import MSDNSServerSettings
from dissect.database.ese.ntds.objects.msds_authnpolicies import MSDSAuthNPolicies
from dissect.database.ese.ntds.objects.msds_authnpolicysilos import MSDSAuthNPolicySilos
from dissect.database.ese.ntds.objects.msds_claimstransformationpolicies import MSDSClaimsTransformationPolicies
from dissect.database.ese.ntds.objects.msds_claimtype import MSDSClaimType
from dissect.database.ese.ntds.objects.msds_claimtypepropertybase import MSDSClaimTypePropertyBase
from dissect.database.ese.ntds.objects.msds_claimtypes import MSDSClaimTypes
from dissect.database.ese.ntds.objects.msds_optionalfeature import MSDSOptionalFeature
from dissect.database.ese.ntds.objects.msds_passwordsettingscontainer import MSDSPasswordSettingsContainer
from dissect.database.ese.ntds.objects.msds_quotacontainer import MSDSQuotaContainer
from dissect.database.ese.ntds.objects.msds_resourceproperties import MSDSResourceProperties
from dissect.database.ese.ntds.objects.msds_resourceproperty import MSDSResourceProperty
from dissect.database.ese.ntds.objects.msds_resourcepropertylist import MSDSResourcePropertyList
from dissect.database.ese.ntds.objects.msds_shadowprincipalcontainer import MSDSShadowPrincipalContainer
from dissect.database.ese.ntds.objects.msds_valuetype import MSDSValueType
from dissect.database.ese.ntds.objects.msimaging_psps import MSImagingPSPs
from dissect.database.ese.ntds.objects.mskds_provserverconfiguration import MSKDSProvServerConfiguration
from dissect.database.ese.ntds.objects.msmqenterprisesettings import MSMQEnterpriseSettings
from dissect.database.ese.ntds.objects.mspki_enterpriseoid import MSPKIEnterpriseOID
from dissect.database.ese.ntds.objects.mspki_privatekeyrecoveryagent import MSPKIPrivateKeyRecoveryAgent
from dissect.database.ese.ntds.objects.msspp_activationobjectscontainer import MSSPPActivationObjectsContainer
from dissect.database.ese.ntds.objects.mstpm_informationobjectscontainer import MSTPMInformationObjectsContainer
from dissect.database.ese.ntds.objects.ntdsconnection import NTDSConnection
from dissect.database.ese.ntds.objects.ntdsdsa import NTDSDSA
from dissect.database.ese.ntds.objects.ntdsservice import NTDSService
from dissect.database.ese.ntds.objects.ntdssitesettings import NTDSSiteSettings
from dissect.database.ese.ntds.objects.ntfrssettings import NTFRSSettings
from dissect.database.ese.ntds.objects.object import Object
from dissect.database.ese.ntds.objects.organizationalperson import OrganizationalPerson
from dissect.database.ese.ntds.objects.organizationalunit import OrganizationalUnit
from dissect.database.ese.ntds.objects.person import Person
from dissect.database.ese.ntds.objects.physicallocation import PhysicalLocation
from dissect.database.ese.ntds.objects.pkicertificatetemplate import PKICertificateTemplate
from dissect.database.ese.ntds.objects.pkienrollmentservice import PKIEnrollmentService
from dissect.database.ese.ntds.objects.querypolicy import QueryPolicy
from dissect.database.ese.ntds.objects.ridmanager import RIDManager
from dissect.database.ese.ntds.objects.ridset import RIDSet
from dissect.database.ese.ntds.objects.rpccontainer import RpcContainer
from dissect.database.ese.ntds.objects.rrasadministrationdictionary import RRASAdministrationDictionary
from dissect.database.ese.ntds.objects.samserver import SamServer
from dissect.database.ese.ntds.objects.secret import Secret
from dissect.database.ese.ntds.objects.securityobject import SecurityObject
from dissect.database.ese.ntds.objects.server import Server
from dissect.database.ese.ntds.objects.serverscontainer import ServersContainer
from dissect.database.ese.ntds.objects.site import Site
from dissect.database.ese.ntds.objects.sitelink import SiteLink
from dissect.database.ese.ntds.objects.sitescontainer import SitesContainer
from dissect.database.ese.ntds.objects.subnetcontainer import SubnetContainer
from dissect.database.ese.ntds.objects.subschema import SubSchema
from dissect.database.ese.ntds.objects.top import Top
from dissect.database.ese.ntds.objects.trusteddomain import TrustedDomain
from dissect.database.ese.ntds.objects.user import User

__all__ = [
    "DMD",
    "NTDSDSA",
    "ApplicationSettings",
    "AttributeSchema",
    "BuiltinDomain",
    "CRLDistributionPoint",
    "CertificationAuthority",
    "ClassSchema",
    "ClassStore",
    "Computer",
    "Configuration",
    "Container",
    "ControlAccessRight",
    "CrossRef",
    "CrossRefContainer",
    "DSUISettings",
    "DfsConfiguration",
    "DisplaySpecifier",
    "DnsNode",
    "DnsZone",
    "Domain",
    "DomainDNS",
    "DomainPolicy",
    "FileLinkTracking",
    "ForeignSecurityPrincipal",
    "Group",
    "GroupPolicyContainer",
    "InfrastructureUpdate",
    "InterSiteTransport",
    "InterSiteTransportContainer",
    "IpsecBase",
    "IpsecFilter",
    "IpsecISAKMPPolicy",
    "IpsecNFA",
    "IpsecNegotiationPolicy",
    "IpsecPolicy",
    "Leaf",
    "LinkTrackObjectMoveTable",
    "LinkTrackVolumeTable",
    "Locality",
    "LostAndFound",
    "MSAuthzCentralAccessPolicies",
    "MSAuthzCentralAccessRules",
    "MSDFSRContent",
    "MSDFSRContentSet",
    "MSDFSRGlobalSettings",
    "MSDFSRLocalSettings",
    "MSDFSRMember",
    "MSDFSRReplicationGroup",
    "MSDFSRSubscriber",
    "MSDFSRSubscription",
    "MSDFSRTopology",
    "MSDNSServerSettings",
    "MSDSAuthNPolicies",
    "MSDSAuthNPolicySilos",
    "MSDSClaimType",
    "MSDSClaimTypePropertyBase",
    "MSDSClaimTypes",
    "MSDSClaimsTransformationPolicies",
    "MSDSOptionalFeature",
    "MSDSPasswordSettingsContainer",
    "MSDSQuotaContainer",
    "MSDSResourceProperties",
    "MSDSResourceProperty",
    "MSDSResourcePropertyList",
    "MSDSShadowPrincipalContainer",
    "MSDSValueType",
    "MSImagingPSPs",
    "MSKDSProvServerConfiguration",
    "MSMQEnterpriseSettings",
    "MSPKIEnterpriseOID",
    "MSPKIPrivateKeyRecoveryAgent",
    "MSSPPActivationObjectsContainer",
    "MSTPMInformationObjectsContainer",
    "NTDSConnection",
    "NTDSService",
    "NTDSSiteSettings",
    "NTFRSSettings",
    "Object",
    "OrganizationalPerson",
    "OrganizationalUnit",
    "PKICertificateTemplate",
    "PKIEnrollmentService",
    "Person",
    "PhysicalLocation",
    "QueryPolicy",
    "RIDManager",
    "RIDSet",
    "RRASAdministrationDictionary",
    "RpcContainer",
    "SamServer",
    "Secret",
    "SecurityObject",
    "Server",
    "ServersContainer",
    "Site",
    "SiteLink",
    "SitesContainer",
    "SubSchema",
    "SubnetContainer",
    "Top",
    "TrustedDomain",
    "User",
]

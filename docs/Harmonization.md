> This document is classified by the Traffic Light Protocol (TLP) as **TLP:WHITE**.

# Data Harmonization Ontology

> release date: 2021-08-20

The proposition of this document is to explicate a data harmonization ontology, which can be used to tailor heterogeneous threat data to the needs of victim notification. We pay special attention to categorize the information in a way that directly serves the needs of early warning. We present four categories, which consist of explicit functional types, each with a specific domain of expertise in mind, namely:

 * **suspected compromise** for incident response
 * **known vulnerabilities** for vulnerability management
 * **public exposure** for configuration management
 * **potential threats** for threat analysis or risk assessment.

Since you are reading this document, you are either working for a party that collects and shares information on observations related to the categories detailed above, you are involved in the operation of an early warning service that disseminates this information to your stakeholders or you are a recipient of this type of information attributed to you. Regardless of your role, you will most likely benefit from perusing this document and gaining a better understanding of how we have approach data harmonization from the victim notification perspective.

## What is data harmonization?

The primary purpose of this document is to help you better deal with the complexity that arises from processing threat data from heterogeneous sources and turning it into threat information that serves early warning. Data harmonization is a contract to always call the same things by the same name and not to call different things by the same name, viz. an IP address is always referred to as an **ip** and a functional **type** always represents a functional classification of an observation, which in turn belongs to one of the **categories** outlined above.

With data harmonization covered briefly, we move on to defining an ontology. An ontology in our case is a higher level abstraction of a language, where each lexeme addresses a discernible characteristic of an observation. Our grammar is thus expressed as sets of key-value pairs, which are straightforward to serialize into flat dictionaries. We reference **observations** as collections of ontology driven key-value pairs. Please note that we use the term **key** to denote an observation schema and the term **attribute** to denote an ontology lexeme.

### Ontology, Schema or Taxonomy

As stated above, an ontology is a higher level abstraction of the semantic characteristics of an observable item. A schema, on the other hand, is a technical contract to transfer or store data in a prescribed format. Both are needed, but we see schemas as derivatives of an underlying semantic representation, which for our purposes is an ontology. In contrast with hierarchical taxonomies, an ontology allows for lexemes outside the core language, provided the definition does not duplicate or redefine that of an already established one. This  calls for harmonization. Consequently, the traditional way of dealing with the unknown in hierarchical taxonomies has been the introduction of the **other** category, which simply fails over time. We have worked hard to avoid this phenomenon.

# Classification Attributes

It is important to be able to classify, prioritize and report relevant actionable observations based on the needs of the recipient; working with a functional ontology, especially for observation categories and types is essential for this, as detailed below.

|attribute|description|
--- | --- |
|category|A category describes the domain of expertise needed to address a given observation. It in itself, is a collection of functional types for a given domain of expertise, e.g. **suspected compromise** must contain observations which merit incident response.|
|type|The type attribute is one of the most crucial pieces of information for any given observation. The main idea of dynamic typing is to keep our ontology flexible, as we need to evolve with the evolving threat landscape presented through the data. Furthermore, the values set for the type attribute should be kept to a minimum to avoid a **type explosion**, which in turn dilutes the business value of dynamic typing.|

Please note that in order to keep communication clear and tailored to the needs of the intended domain, we retain a 1:1 mapping between a category and a type, i.e. only the type **test** is a member of multiple categories. All the other types belong to a single category.

## Categories and Types

As stated above, a category defines an input for a specific domain of expertise. At present we define four distinct categories as follows:

|attribute|domain|description|
--- | --- | --- |
|suspected compromise|incident response|This category of information details specific recipient assets, which have been observed by a third party to be compromised.|
|known vulnerabilities|vulnerability management|This category of information details technical vulnerabilities, which at present are often enumerated through Common Vulnerabilities and Exposures and which warrant a fix to be deployed to address them.|
|public exposure|configuration management|This category of information details services or ports which are publicly exposed to the Internet.|
|potential threats|threat analysis or risk assessment|This category of information enumerates observations, which can cause harm to the affected organization, such as a service being blocked by third parties, but are not specific enough to attribute the harm without further analysis.|

Below, we explicate each category in more detail, as well as enumerate the type values, which belong to a given category. The **type** values offer a data-backed taxonomy for classifying observations in a uniform manner. A concise yet functional classification system enables you to make informed decisions about the state of your network estate even in real-time. It is geared towards simplicity and automation, which in turn will help you better understand the big picture as well.

### Suspected Compromise

The traditional form of victim notification relates to observations that detail a network resource which is believed to have already been compromised. A good example of this type of activity is a malware infected machine, which has been observed to reach out to a command and control server despite the security controls of the affected organization. Below, we enumerate the functional types which detail malice in a way, which should immediately instigate incident response activities in the affected organization.

|attribute|description|impact|
--- | --- | --- |
|alert|This type of observation refers to detection rule or identity based matches, which cannot be attributed to a more specific functional type.|The system triggering these alerts should be triaged, taking into account the indicator which has triggered the alert and the constraints of the local environment.|
|backdoor|These observations refer to hosts which have been compromised and/or backdoored by a third party.|Threat actors may use this functionality to gain remote access to the machine or service.|
|botnet drone|This type of observation details hosts which have been observed to call out to a command and control server.|These hosts are likely to have been infected by a piece of malware and are controlled by threat actors.|
|brute-force|A host which has been observed to perform brute-force attacks over a given application protocol, e.g. ssh.|These hosts are likely to be infected by malware or compromised and are trying to break into other computers or services.|
|c&c|These observations detail hosts, which are controlling malware infected machines, a.k.a. botnet drones.|Threat actors use these hosts to command their botnets and often the host itself has been compromised as well.|
|compromised server|This type of observation details a server or service has been compromised by a third party.|These hosts or services are under threat actor control to do their bidding.|
|ddos infrastructure|This type refers to various parts of DDoS botnet infrastructure.|These hosts or services have most likely facilitated DDoS attacks even if they have not necessarily been compromised. They may for example offer a UDP-based vulnerable service, which has been spoofed to facilitate a reflected attack against a third party. This in turn may consume the upstream bandwidth of the host during an attack.|
|defacement|This type of observation refers to hacktivism, which on a technical level is indicative suspected compromise.|This host is likely to have been compromised by a third party and very often is used for other criminal activities as well.|
|dropzone|This type of observation refers to a resource which is used to store stolen user data.|Personally identifyiable information is often stored unlawfully on these hosts or services.|
|exploitation|This type of observation refers to hosts attempting to exploit a vulnerable service on a third party system.|These hosts are likely to have been compromised and are trying to break into other hosts or services.|
|exploit url|This type of observation details an exploit kit, which served through a malicious URL.|These URLs are used by the threat actors as a mechanism to break into vulnerable machines.| 
|malware configuration|Thes observations point to resources which update botnet drones with a new configurations.|These hosts or services function as part of threat actor infrastructure and are often compromised by threat actors.|
|malware url|An observation referencing a malware URL is the most common resource associated with malware distribution.|These hosts are serving pieces of malware to infect new machines and are often compromised by threat actors.|
|phishing|This observation type most often refers to a URL or domain name used to defraud the users of their credentials.|These URLs or domain names are served to potential victims to try to steal their credentials to a third party service. These hosts are often also compromised by threat actors.|
|ransomware|This observation type refers to a specific type of suspected compromise, where the host has been hijacked for ransom by the criminals.|The storage resources of these hosts are encrypted by the criminals for ransom or sabotage. This in turn, may lead to encryption of storage resources for an entire organization.|
|scanner|This observation type refers to machines which are performing port or vulnerability scanning attempts in general.|These hosts are scanning for vulnerable services to enable threat actors to compromise them. The host doing the scanning are often compromised or infected as well.|
|spam infrastructure|These observations detail resources which make up a spammer's infrastructure, be it a harvester, dictionary attacker, URL, spam etc.|These hosts will most likely be blocked because they are participating in spamming activities.|
|test|Used for testing purposes.|These observations can be used to test an early warning service for example, without impacting the functionality of the service.|

### Known Vulnerabilities

This category of information refers to observations, which detail a technical vulnerability present in a service. For early warning, it is important to denote the ip, vulnerability, protocol, service and port as well. For generic vulnerability management, the affected product and remediation information will also be useful.

|attribute|description|impact|
--- | --- | --- |
|ddos amplifier|These observations refer to misconfigured network services, which are vulnerable to DDoS reflection often over UDP.|Even if this vulnerability does not directly affect the confidentiality or integrity of the host in question, the resource or upstream bandwidth consumption can affect availability.|
|vulnerable service|These observations refer to specific technical vulnerabilities present on a network service, which have been assigned a CVE by MITRE.|The CVE assigned to the vulnerability affect the host in various ways. The CIA triad and CVSS score are metrics, which detail the severity of the vulnerability. Remote code execution is a good example of a severe impact.| 
|test|Used for testing purposes.|These observations can be used to test an early warning service for example, without impacting the functionality of the service.|

### Public Exposure

Public exposure denotes observations which are useful in trying to minimize the recipient organization's  attack surface. Observations can take place on the level of a network service or that of an open port and its transport protocol. Exposed services are akin to vulnerabilities, but the major difference lies in their remediation. Often an exposed service or port is remediated by changing a firewall rule, an access control list or configuration option and not through patching a specific vulnerability in the implementation. Consequently, all observations in this category serve configuration management.

|attribute|description|impact|
--- | --- | --- |
|exposed service|These observations relate to network services, which should not be directly exposed to the Internet.|The implementations of these types of services have not been designed with the needs of the Internet in mind and can often be trivially compromised. A good example of this type of a service is RDP.|
|open service|This type refers to network services, which are publicly exposed to the Internet. This may be intentional or the result of a misconfiguration.|Even if scanning for this service has not identified a specific vulnerability, unintentionally exposed network services increase the attack surface and may lead to compromise. A good example of this type of a service is FTP.|
|open port|These types of observations relate to hosts which expose specific ports to the Internet, but the observations do not specify the exact service in question.|Open ports, which do have a service responding to requests from anyone will increase the attack surface of a given organization.|
|test|Used for testing purposes.|These observations can be used to test an early warning service for example, without impacting the functionality of the service.|

### Potential Threats

Potential threats denote a category of observations which attribute a potential harm to an organization. The observations will need to be further validated by the recipient to see which domain of expertise can benefit from the analysis result, if any.

|attribute|description|impact|
--- | --- | --- |
|artifact|Artifacts refer to host-based indicators, such as checksums, file paths or detection rules.|These observations do not directly reference a compromise, rather can be used for monitoring and detection.|
|attribution|Observations that can be attributed to malicious activity, which are not detailed enough to action on, from the victim notification perspective.|These observations require further assessment or analysis.|
|blocked resource|Some sources provide reputation lists which clearly refer to abusive behavior (such as spamming) but fail to denote the exact reason why a given identity has been listed. The justification may be anecdotal or missing entirely.|Services appearing on these lists will have difficulty to operate normally, as their service specific communication will be blocked by third parties.|
|breached data|Observations on entire data dumps that often reside on the dark web and can be associated with an organization.|The breached data dump is a sign of suspected compromise, but further analysis is needed to ascertain where the breach has taken place and who is affected by it.|
|compromised account|Observations on leaked user credentials, which have been taken from a compromised online service.|The compromised credentials may lead to further unauthorized use through password re-use even if the compromised service is not part of the report recipient's infrastructure.|
|cve|This type of observation identifies a product and a version of software, which contains a specific vulnerability.|These observations do not detail the affected host or service, rather than they can be used to identify such services especially if they are not directly exposed to the Internet or refer to client side vulnerabilities.|
|ddos target|This observation type refers to an intended target of a DDoS attack.|A host or service has been subjected to DDoS traffic, which may have impacted operations.|
|test|Used for testing purposes.|These observations can be used to test an early warning service for example, without impacting the functionality of the service.|

# Core Attributes

For an observation to be actionable and able to reach the right end recipient, various attributes must to be present and defined in the correct manner.

## Feed Attributes

|attribute|description|
--- | --- |
|feed|Lower case name for the feed, e.g. phishtank.|
|feed code|Alternative code name for the feed in case it cannot be shared e.g. dgfs, hsdag etc.|
|feeder|Name of the organization providing one or more data feeds, e.g. shadowserver.|
|feed url|The URL of a given abuse feed, where applicable.|
|source|Often a feed may be a collection of events from various sources. In this case it may be prudent to identify the different sources of which the feed is comprised.

## Time

All time stamps should be normalized to UTC. If the source reports only a date, you should not invent a time stamp.

|attribute|description|
--- | --- |
|observation time|The time an observation system processed the observation. This timestamp becomes especially important should you perform your own augmentation on a domain name collected from a source. The mechanism to denote the attributed elements with reference to the source provided is detailed below under Reported Identity.|
|source time|Time reported by a source or feed. Some sources only report a date, which may be used here if there is no better observation. N.B. this time is the most important point of reference to pin down the observation by the end user recipient.|

A good way to represent timestamps is this [ISO 8601 combined date-time representation](http://en.wikipedia.org/wiki/ISO_8601#Combined_date_and_time_representations): ```YYYY-MM-DD HH:MM:SSZ```. We have omitted the T for readability, since:

"By mutual agreement of the partners in information interchange, the character [T] may be omitted in applications where there is no risk of confusing a date and time of day representation with others defined in this International Standard." (ISO 8601:2004(E). ISO. 2004-12-01. 4.3.2 NOTE)

## Identity

The observation type defines the way the attributes of an observation need to be interpreted as a whole. For a botnet drone, the attributes refer a compromised machine, whereas for a command and control server they refer the server itself. For example, a port for a botnet drone is the source port of the connection to the c&c service.

|attribute|description|
--- | --- |
|as name|The registered name for an autonomous system.|
|asn|Autonomous system number.|
|bgp prefix allocated|The date when a Regional Internet Registry (RIR) such as RIPE NCC or ARIN allocated a given BGP prefix.|
|bgp prefix|A CIDR associated to an autonomous system.|
|domain name|DNS domain name. http://en.wikipedia.org/wiki/Domain_name|
|email address|An email address, the interpretation of which is based on the observation type.|
|ip|IPv4 or IPv6 address.|
|port|The port through which the observed activity is taking place. For example a command and control server report will most likely contain a port which is directly related to the reported IP or host operating as the c&c.|
|registry|The IP registry, RIR, which allocated a given IP address or netblock.|
|reverse dns|A Reverse DNS name acquired through a reverse DNS lookup on an IP address. Note: Record types other than PTR records may also appear in the reverse DNS tree. http://en.wikipedia.org/wiki/Reverse_DNS_lookup|
|url|A URL denotes an observation, which refers to a malicious resource or vulnerable endpoint, whose interpretation is defined by the observation type. For example a URL with the observation type phishing refers to a phishing resource.|

### Source Identity

Source identity attributes should be used to complement the observation about a specific observation type. In other words, this information is complementary to the main identity attributes described above.

|attribute|description|
--- | --- |
|source as name|The autonomous system name from which the connection originated.|
|source asn|The autonomous system number from which originated the connection.|
|source cc|The country code of the IP from which the connection originated.|
|source domain name|A DNS name related to the host from which the connection originated.|
|source ip|The IP observed to initiate the connection.|
|source port|The port from which the connection originated.|

### Destination Identity

As stated above, the meaning of each observation needs to be interpreted with reference to the observation type. In the context of a botnet drone, for example, a destination IP and port usually denote the command and control server. I.e. the port attribute in those cases should not be referred to as the source port, rather than just *port*. For a scanner observation, the IP and port will be the source IP and port of the connection and the destination IP and port will denote the scanned target.

|attribute|description|
--- | --- |
|destination as name|The autonomous system name of the destination of the connection.|
|destination asn|The autonomous system number of the destination of the connection.|
|destination cc|The country code of the IP which was the end-point of the connection.|
|destination domain name|The DNS name related to the end-point of a connection.|
|destination ip|The end-point of the connection.|
|destination port|The destination port of the connection.|

### Local Identity

|attribute|description|
--- | --- |
|os name|Operating system name.|
|os version|Operating system version.|
|user agent|Some feeds report the user agent string used by the host to access a malicious resource, such as a command and control server.|
|username|A username of a user account.|

### Reported Identity

Each early warning service organization should define a policy which outlines those attributes used as primary elements of an observation. Often the source feeds perform their own attribution but you may choose to correlate their attributive elements against your own or those of a third party. In practice, this means that your harmonization process should prefix the keys with the **reported** keyword, to denote that you have decided to perform the attribution on your own. The list below is not comprehensive; rather it is a list of common things you may want to observe yourself. Moreover, if you choose to perform your own attribution, the **observation time** will become your authoritative point of reference in relation to the new attributes.

|attribute|description|
--- | --- |
|reported as name|The autonomous system name registered to the reported ASN.|
|reported asn|The autonomous system number related to the resource which was reported by the source feed.|
|reported cc|The country code of the reported IP.|
|reported ip|Should you perform your own attribution on a DNS name referred to by host, the IP reported by the source feed is replaced.|

### Geolocation

We acknowledge IP geolocation is not an exact science, and our analysis has shown that attribution sources have varying opinions about the physical location of an IP address at a given time. This is why we recommend to augment the data with as many sources as you have available and make a decision which source to use for the country code (cc) attribute based on those answers.

|attribute|description|
--- | --- |
|cc|Each service provider should define a logic how to assign a value for the cc key. You may decide to trust the opinion of a single source or apply logical operations on multiple sources. The country code is expressed as an ISO 3166 two-letter country code.|
|city|Some geolocation services refer to city-level geolocation.|
|country|The country name derived from the ISO 3166 country code (assigned to cc above).|
|latitude|Latitude coordinate derived from a geolocation service such as the MaxMind GeoIP database.|
|longitude|Longitude coordinate derived from a geolocation service such as the MaxMind GeoIP database.|

## Additional Attributes

The idea behind the additional attributes is to present generic observation metadata which complements the identity or temporal information about the observed activity, be it suspected compromise, known vulnerabilities, public exposure or potential threats. In addition, the purpose of this information is to give more context to the observation type denoted by the **type** attribute.

|attribute|description|
--- | --- |
|abuse contact|An abuse contact email address for an IP network.|
|additional information|Sometimes it may be necessary to relay a an additional piece of information to the report recipient related to the specific context at hand. So in a sense it is a placeholder for useful context dependent information, which would be otherwise difficult to convey without changing the schema.|
|comment|Free text commentary about the abuse event augmented by an analyst.|
|description url|A description URL is a link to a further description of the observation in question.|
|description|A concise free-form textual description of the observation, which should make it easier for the recipient to interpret it.|
|http request|Some feeders report HTTP requests instead of URLs. The feeders may call them URLs but for the sake of interoperability with automation, such events should be placed under the "http request" key as there is no guarantee that the protocol scheme is HTTP.|
|malware family|A malware family name, in lower case.|
|missing data|If an observation is missing a known piece of data (such as an **ip** for example), the reference to this fact may be inserted here.|
|protocol|The protocol attribute describes the application protocol on top of the transport which relates to the observation in question; that is, "protocol=ssh" for SSH brute-force attacks is more descriptive than "protocol=tcp". In this case the transport protocol should be referenced by that key, "transport protocol=tcp".|
|service|In addition to describing a port and protocol for a given observation, one may need to describe the service which is listening on that port which is described by the observation, such as a publicly exposed vulnerability.|
|severity|Often observations need to be prioritized and technical severity can be used to denote the urgency of the observation to the recipient, e.g. low, medium, high.|
|status|Observed status of a network resource such as a phishing URL, dropzone, command and control server; for example, online, offline.|
|target|Some sources such as phishing feeds designate the target of a phishing campaign.|
|tracking id|Some sources and applications use an identifier to denote a context for an observation. This context may attribute a threat actor, case number or any other contextual information which is bundled with the observation.|
|transport protocol|Some feeds report a protocol denoting the observed transport (for example, tcp, udp). This should be recorded appropriately should the protocol attribute denote the protocol of a vulnerable service for example.|
|uri|For various technical reasons feeders often present URI references in their feeds instead of URLs. A URI reference is sometimes missing the scheme element, even if the authority and path elements are present as defined by the RFC3986. For brevity, we use the uri attribute to denote URIs and URI references.|
|uuid|The purpose of a uuid is to denote an identifier, which uniquely identifies a single observation. For example, UUIDs generated with Python should generated using the uuid.uuid4() function, based on [RFC4122](http://tools.ietf.org/html/rfc4122). Note that "uuid" serves a different function than the tracking id.|
|vulnerability|Sometimes it is necessary to provide a short description of a vulnerability reported by a source. This helps in correlating the vulnerabilities across sources. Vulnerability may be a CVE, name such as Heartbleed, or a weakness related to the attack surface such as firewall configuration.|

### Artifact Attributes

Host-based artifacts play a role in incident handling, and having a means to relay these in a uniform manner through automation is essential. At present, we identify two main categories for artifacts:

 * hashes of malicious content
 * functional or formal descriptions of malicious content.

|attribute|description|
--- | --- |
|artifact content|A funtional or rule-based description of malicious content.|
|artifact content type|Functional typing for the artifact content in question, e.g. a detection rule or a functional artifact such as a registry key or mutex.|
|artifact hash|A string depicting a checksum or hash of a file, be it a malware or other sample.|
|artifact hash type|The hashing algorithm used for artifact hash type above, such as MD5 or SHA-3 etc.|

## Topic- or Provider-Specific Attributes

As stated above, the basic premise of an ontology is to specify a core language which is able to communicate the relevant aspects of a topic in an effective manner. This leaves room for topic-specific lexemes outside the generic terminology; this is especially true in the context of reporting emerging trends, where a single source may start reporting on a topic and other follow suit.

For these reasons, we occasionally leave out some lexemes from the ontology and bring in new ones which represent a generic topic. This approach does not detract from the ontology nor its communicative function, as the core attributes communicate the relevant aspects effectively. Topic- or provider-specific attributes can thus be part of an observation name space.

It is thus important to avoid collision with the core ontology name space. In other words, topic- or provider-specific attributes are new emerging attributes which may in time become part of the ontology if they are adopted to describe a facet of a generic topic.

We have for example decided to use the "cc" attribute above as the authoritative country code denominator. Provider specific attributes are then prefixed with a provider name, e.g. "cymru cc" or "geoip cc".

## Harmonization Best Practices

There are many things you have to take into account when harmonizing heterogeneous datasets. The established attributes in this ontology should help you on your way when dealing with topic- or provider-specific attributes. In general, the attribute names must be **lower case** and use white space, " ", instead of underscores, "\_"; for example, "DNS\_Version" should be harmonized into "dns version".

We recognize that for traditional database schemas this approach may be challenging, but converting spaces into underscores in the attribute names should not be an impossible undertaking. The idea of the ontology, after all, is to be a human readable abstraction.

On the note of human readability, we endeavour to strike a balance between attribute name length and readability. For technical people, "src port" may be natural, but "source port" is more readable; on the other hand, "reverse dns" instead of "reverse domain name system name" is more practical. The important point is to have a clear naming convention and adhere to it: "destination domain name" is unwieldy, but "dst domain name" or "dst dns" would not use the same rationale as "domain name".

In summary, the underlying idea of this ontology is to provide a good foundation on which to build, whether the use case is filtering, aggregation, reporting or alerting. Not having to deal with, say, 32 names for an IP address makes life a lot easier at the end of the pipeline.

# History of this Document

A public version of this document has been iterated over, since 2012. Originally, it was a collaboration between numerous CSIRT actors (CERT-EU, CERT-AT, CERT-FI, CERT.PT) and Codenomicon. The current version of this document represents the practical collaboration between national CSIRT teams such as [CERT-BE](http://www.cert.be/), [NCSC](http://www.ncsc.gov.uk), [NCSC-FI](https://www.ncsc.fi) and [Arctic Security](http://www.arcticsecurity.com), a commercial company.

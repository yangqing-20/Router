/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
enum mod{
ARP_MOD,
ICMP_MOD,
IPV4_MOD,
ETHERNET_MOD
};

enum failed_mod{
TIME_EXCEEDED,
PORT,
HOST,
NET
};

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
//This method is called each time the router receives a packet on
//    * the interface.  The packet buffer \p packet and the receiving
//    * interface \p inIface are passed in as parameters. The packet is
//    * complete with ethernet headers.
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIface(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  if (!checkHeader(packet,ETHERNET_MOD,inIface)) {
        return;
    }

    // Get header info
  uint16_t ethtype = ethertype((uint8_t*)packet.data());
    if (ethtype == ethertype_arp) {
        handleArpPacket(packet, inIface);
    } else if (ethtype == ethertype_ip) {
        handleIPv4Packet(packet, inIface);
    }
    else{ // Wasn't a correct type
        std::cerr << "ERROR: This packet wasn't ARP or IPv4" << std::endl;
        return;
        }
}

void SimpleRouter::handleArpPacket(const Buffer& packet, const std::string& inIface) {
    if (!checkHeader(packet,ARP_MOD,inIface)) {
        return;
    }

    struct arp_hdr* hARP = (struct arp_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    const Interface* iface = findIface(inIface);

    // ignore ARP if the target ip is not router's IP
    if (hARP->arp_tip != iface->ip) {
        return;
    }

    if (ntohs(hARP->arp_op) == 0x0001) {
        handleArpRequest(packet, inIface);
    } else if (ntohs(hARP->arp_op) == 0x0002) {
        handleArpReply(packet);
    } else
        std::cerr << "ERROR: ARP wasn't a request or reply" << std::endl;
}

void SimpleRouter::handleArpReply(const Buffer& packet) {
    struct arp_hdr* hARP = (struct arp_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    uint32_t IP = hARP->arp_sip;
    Buffer MAC(hARP->arp_sha, hARP->arp_sha + ETHER_ADDR_LEN);

    auto request = m_arp.insertArpEntry(MAC, IP);
    if (request != nullptr) {
        for (auto pendingPacket : request->packets) {
            handlePacket(pendingPacket.packet, pendingPacket.iface);
        }
        m_arp.removeRequest(request);
    }
}

// check header for ether/icmp/ipv4/arp
bool SimpleRouter::checkHeader(const Buffer& packet,int mod,std::string IfaceName) {
    switch(mod){
    case IPV4_MOD:{
         // Check the length
        if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)) {
            return false;
        }

        struct ip_hdr* hIPv4 = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

        uint16_t checksum = hIPv4->ip_sum;
        hIPv4->ip_sum = 0;
         // Check the checksum
        if (cksum(hIPv4, sizeof(struct ip_hdr)) != checksum) {
            hIPv4->ip_sum = checksum;
            return false;
        } else {
            hIPv4->ip_sum = checksum;
            return true;
        }
        break;
    }
    case ICMP_MOD:{
        if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)) {
            return false;
        }
        struct icmp_hdr* hICMP = (struct icmp_hdr*)(packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));

        uint16_t checksum = cksum(hICMP, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
        if (checksum != 0xffff) {
            return false;
        }
        return true;
        break;
    }
    case ARP_MOD:{
        // Check the ARP header

        //ARP packet is too short,
        if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)) {
            return false;
        }
        const uint8_t* buf = packet.data();
        // Check the ARP header
        const arp_hdr* arp = (arp_hdr*)(buf + sizeof(ethernet_hdr));
        if (arp->arp_hrd != htons(arp_hrd_ethernet) || arp->arp_pro != htons(ethertype_ip) || arp->arp_hln != ETHER_ADDR_LEN || arp->arp_pln != 0x04) { // Check Hardware Type, Protocol Type, Hardware Address Length, Protocol Address Length
            return false;
        }
        // Check the opcode
        if (arp->arp_op != htons(arp_op_request) && arp->arp_op != htons(arp_op_reply)) {
          return false;
        }
    
        // Check the destination IP address
        const Interface* iface = findIface(IfaceName);
        if (arp->arp_tip != iface->ip) {
          return false;
        }
        return true;

        break;
    }
    case ETHERNET_MOD:{
          if (packet.size() < sizeof(struct ethernet_hdr)) {
            std::cerr << "packet.size() < sizeof(struct ethernet_hdr) return false" << std::endl;
            return false;
        }
        const uint8_t* buff = packet.data();
        uint16_t type = ethertype(buff);
        struct ethernet_hdr* hEther = (struct ethernet_hdr*)packet.data();
        if (type != ethertype_arp && type != ethertype_ip) {
            return false;
        }
        const auto Iface = findIface(IfaceName);
        // corresponding MAC address of the interface
        if (memcmp(hEther->ether_dhost, Iface->addr.data(), ETHER_ADDR_LEN) == 0) {
            return true;
        }
        // broadcast
        if (memcmp(hEther->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN) == 0) {
            return true;
        }
        return false;
        break;
        }
    }
    std::cerr << "SimpleRouter::checkHeader mod is wrong" << std::endl;
    return false;
}


void SimpleRouter::handleArpRequest(const Buffer& packet, const std::string& inIface) {
    struct ethernet_hdr* hEther = (struct ethernet_hdr*)packet.data();
    struct arp_hdr* hARP = (struct arp_hdr*)((uint8_t*)hEther + sizeof(struct ethernet_hdr));

    // copy the old packet
    Buffer reply(packet);
    // Create ethernet header
    struct ethernet_hdr* hReplyEther = (struct ethernet_hdr*)reply.data();
    struct arp_hdr* hReplyARP = (struct arp_hdr*)((uint8_t*)hReplyEther + sizeof(struct ethernet_hdr));

   
     // get Interface
    const Interface* inface = findIface(inIface);
    // swap Ether dst and src
    memcpy(hReplyEther->ether_dhost, hEther->ether_shost, ETHER_ADDR_LEN);
    memcpy(hReplyEther->ether_shost, inface->addr.data(), ETHER_ADDR_LEN);

    // swap ARP dst and src
    memcpy(hReplyARP->arp_tha, hARP->arp_sha, ETHER_ADDR_LEN);
    memcpy(hReplyARP->arp_sha, inface->addr.data(), ETHER_ADDR_LEN);
    hReplyARP->arp_tip = hARP->arp_sip;
    hReplyARP->arp_sip = hARP->arp_tip;
    hReplyARP->arp_op = htons(0x0002);

 // Send reply packet
    sendPacket(reply, inface->name);
}



void SimpleRouter::handleIPv4Packet(const Buffer& packet, const std::string& inIface) {

    if (!checkHeader(packet,IPV4_MOD,inIface)) {
        return;
    }

    struct ip_hdr* hIPv4 = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    if (findIface(hIPv4->ip_dst) != nullptr) {  // destined to the router
        if (hIPv4->ip_p == 0x0006 || hIPv4->ip_p == 0x0011) { // TCP or UDP
            replyICMPFailed(packet,PORT);
        } else if (hIPv4->ip_p == ip_protocol_icmp) {
            if (!checkHeader(packet,ICMP_MOD,inIface)) {
                return;
            }

            struct icmp_hdr* hICMP = (struct icmp_hdr*)((uint8_t*)hIPv4 + sizeof(struct ip_hdr));
            if (hICMP->icmp_type == 8 && hICMP->icmp_code == 0) {
                replyICMP(packet, 0, 0);
            }
        } 
    } else {  // datagrams to be forwarded
        forwardIPv4Packet(packet, inIface);
    } 
}


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}



void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

// find by ip/name/mac
const Interface*
SimpleRouter::findIface(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIface(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIface(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}



void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}





// New Func

//Arp
void SimpleRouter::sendArpRequest(uint32_t ip) {

    Buffer request(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));
    struct ethernet_hdr* hEther = (struct ethernet_hdr*)(request.data());
    struct arp_hdr* hArp = (struct arp_hdr*)((uint8_t*)hEther + sizeof(struct ethernet_hdr));

    // get Interface
    RoutingTableEntry routingEntry;
    try {
        routingEntry = m_routingTable.lookup(ip);
    } catch (std::runtime_error& e) {
        std::cerr << "No routing entry for ip: " << ip << std::endl;
        return;
    }
    
    auto outIface = findIface(routingEntry.ifName);
    if (outIface == nullptr) {
        std::cerr << "No interface for ip: " << ip << std::endl;
        return;
    }

    // build Ethernet header
    memcpy(hEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    memset(hEther->ether_dhost, 0xff, ETHER_ADDR_LEN);  // broadcast
    hEther->ether_type = htons(ethertype_arp);

    // build Arp header
    hArp->arp_hrd = htons(0x0001);
    hArp->arp_pro = htons(0x0800);
    hArp->arp_hln = 0x06;
    hArp->arp_pln = 0x04;
    hArp->arp_op = htons(0x0001);
    memcpy(hArp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
    hArp->arp_sip = outIface->ip;
    memset(hArp->arp_tha, 0xff, ETHER_ADDR_LEN); 
    hArp->arp_tip = ip;

    sendPacket(request, outIface->name);
}


// IPv4
void SimpleRouter::forwardIPv4Packet(const Buffer& packet, const std::string& inIface) {
    struct ip_hdr* hIPv4 = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    // check TTL
    if (hIPv4->ip_ttl - 1 <= 0) {
        replyICMPFailed(packet,TIME_EXCEEDED);
        return;
    }

    RoutingTableEntry routingEntry; // get routing entry
    try {
        routingEntry = m_routingTable.lookup(hIPv4->ip_dst);
    } catch (const std::runtime_error& error) {
        replyICMPFailed(packet,NET);
        return;
    }

    uint32_t nextIP = routingEntry.gw;
    if (nextIP == 0){
        nextIP = hIPv4->ip_dst;
    }
    auto arpEntry = m_arp.lookup(nextIP);
    if (arpEntry == nullptr) {  // don't have a arp entry yet
        // queue request
        m_arp.queueRequest(hIPv4->ip_dst, packet, inIface);
        return;
    }

    // make a copy
    Buffer dispatch = packet;
    struct ethernet_hdr* hDispatchEther = (struct ethernet_hdr*)dispatch.data();
    struct ip_hdr* hDispatchIPv4 = (struct ip_hdr*)((uint8_t*)hDispatchEther + sizeof(struct ethernet_hdr));

    const auto outIface = findIface(routingEntry.ifName);
    // prepare ethernet header
    memcpy(hDispatchEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    memcpy(hDispatchEther->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
    // prepare ip header
    hDispatchIPv4->ip_ttl --;
    hDispatchIPv4->ip_sum = 0;
    hDispatchIPv4->ip_sum = cksum(hDispatchIPv4, sizeof(struct ip_hdr));

    sendPacket(dispatch, outIface->name);
}


// ICMP
void SimpleRouter::replyICMP(const Buffer& packet, uint8_t icmp_type, uint8_t icmp_code) {
    struct ethernet_hdr* hEther = (struct ethernet_hdr*)(packet.data());
    struct ip_hdr* hIPv4 = (struct ip_hdr*)((uint8_t*)hEther + sizeof(struct ethernet_hdr));


    Buffer reply(packet);
    struct ethernet_hdr* hReplyEther = (struct ethernet_hdr*)reply.data();
    struct ip_hdr* hReplyIPv4 = (struct ip_hdr*)((uint8_t*)hReplyEther + sizeof(struct ethernet_hdr));
    struct icmp_t3_hdr* hReplyICMPT3 = (struct icmp_t3_hdr*)((uint8_t*)hReplyIPv4 + sizeof(struct ip_hdr));

    // get Interface
    const auto routingEntry = m_routingTable.lookup(hIPv4->ip_src);  // reply to src ip
    const auto outIface = findIface(routingEntry.ifName);

    // build Ethernet header
    memcpy(hReplyEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    memcpy(hReplyEther->ether_dhost, hEther->ether_shost, ETHER_ADDR_LEN);  // send back
    hReplyEther->ether_type = htons(ethertype_ip);

    // build IP
    hReplyIPv4->ip_id = 0;
    hReplyIPv4->ip_p = ip_protocol_icmp;
    hReplyIPv4->ip_ttl = 64;
    hReplyIPv4->ip_sum = 0;
    hReplyIPv4->ip_src = outIface->ip;
    // hReplyIPv4->ip_src = hIPv4->ip_dst;
    hReplyIPv4->ip_dst = hIPv4->ip_src;
    hReplyIPv4->ip_sum = cksum(hReplyIPv4, sizeof(struct ip_hdr));

    // build ICMP T3
    hReplyICMPT3->icmp_type = icmp_type;
    hReplyICMPT3->icmp_code = icmp_code;
    hReplyICMPT3->icmp_sum = 0;
    if (icmp_type == 11 || icmp_type == 3) {
        memcpy((uint8_t*)hReplyICMPT3->data, (uint8_t*)hIPv4, 28);
    }
    hReplyICMPT3->icmp_sum = cksum(hReplyICMPT3, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));

    sendPacket(reply, outIface->name);
}






// icmp fail for different reasons
void SimpleRouter::replyICMPFailed(const Buffer& packet,int mod) {
    switch(mod){
        case TIME_EXCEEDED:{
            replyICMP(packet, 11, 0);
            return;
            break;
            }
        case PORT:{
            replyICMP(packet, 3, 3);
            return;
            break;
        }
        case HOST:{
            replyICMP(packet, 3, 1);
            return;
            break;
        }
        case NET:{
            replyICMP(packet, 3, 0);
            return;
            break;
        }
    }
    std::cerr << "SimpleRouter::replyICMPFailed(const Buffer& packet,int mod) mod wrong "<< std::endl;
    return;
}


 } // namespace simple_router
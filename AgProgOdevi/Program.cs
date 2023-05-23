using System;
using System.Threading;
using System.Collections.Generic;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Core.Extensions;
using System.Net;
using System.Net.NetworkInformation;
using System.Timers;

namespace AgProgOdevi
{
    class Program
    {
        static Dictionary<ushort, Packet> Cevaplar = new Dictionary<ushort, Packet>();
        static MacAddress sourceMAC;
        static MacAddress destinationMAC;
        static string sourceIP_str;
        static IpV4Address sourceIP;
        static IpV4Address destinationIP;
        static LivePacketDevice selectedDevice;
        static Dictionary<ushort, DateTime> pingID = new Dictionary<ushort, DateTime>();





        static void Main(string[] args) /*main*/
        {

            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;


            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);
            // Take the selected adapter
            selectedDevice = allDevices[deviceIndex - 1];

            sourceMAC = selectedDevice.GetMacAddress(); //finds and uses the MAC address of the selected device
            destinationMAC = new MacAddress("[address here]"); //physical addresses of default gateway
            sourceIP_str = null;//empty string

            foreach (DeviceAddress address in selectedDevice.Addresses) 
            {
                if (address.Address.Family == SocketAddressFamily.Internet) //internet = ipv4
                    sourceIP_str = address.Address.ToString().Substring(9, address.Address.ToString().Length - 9);
                //Console.WriteLine(address.Address.ToString()); 
            }


            sourceIP = new IpV4Address(sourceIP_str); 
            destinationIP = new IpV4Address("8.8.8.8");

            Thread thread2 = new Thread(Dinle);
            Thread thread1 = new Thread(PingDNS);


            thread1.Start();
            thread2.Start();
        }







        static void Dinle()
        {
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {

                // Compile the filter
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and src " + "8.8.8.8")) //sourceIP.ToString()
                {
                    communicator.SetFilter(filter);
                }
                Console.WriteLine("DNS cevaplari dinleniyor...");

                // Retrieve the packets
                Packet p;
                do
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out p);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            continue;
                        case PacketCommunicatorReceiveResult.Ok: 
                            IpV4Datagram ip = p.Ethernet.IpV4;
                            UdpDatagram udp = ip.Udp;
                            DnsDatagram dns = udp.Dns;
                            ushort id = dns.Id;
                            

                            lock (Cevaplar) //Locked because its a critical section
                            {
                                Cevaplar.Add(id, p);
                            }
                            break;
                        default:
                            throw new InvalidOperationException("The result " + result + " should never be reached here");
                    }
                } while (true);
            }
        }






        private static void PingDNS() /*Sends a DNS package*/
        {
           
            using (PacketCommunicator communicator = selectedDevice.Open(200, 
                                                                         PacketDeviceOpenAttributes.Promiscuous, 
                                                                         1000)) 
            {
                for (ushort i = 0; i < 1; i++)
                {
                    var paketveID = BuildDnsPacket(i, i); 
                                            //Console.WriteLine(paketveID.Item2.ToString());
                    pingID.Add(i, DateTime.Now);
                    communicator.SendPacket(paketveID.Item1); 

                    var t = new Thread(() => Yorumla(i));
                    t.Start();
                    Thread.Sleep(1000);
                }
            }

        }
        private static Tuple<Packet, ushort> BuildDnsPacket(ushort ID, ushort Identifier) //Builds a DNS package
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = sourceMAC,
                    Destination = destinationMAC,
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = sourceIP,
                    CurrentDestination = destinationIP,
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = Identifier,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            UdpLayer udpLayer =
                new UdpLayer
                    {
                        SourcePort = 4050,
                        DestinationPort = 53,
                        Checksum = null, // Will be filled automatically.
                        CalculateChecksumValue = true,
                    };

            DnsLayer dnsLayer =
                new DnsLayer
                    {
                        Id = ID,
                        IsResponse = false,
                        OpCode = DnsOpCode.Query,
                        IsAuthoritativeAnswer = false,
                        IsTruncated = false,
                        IsRecursionDesired = true,
                        IsRecursionAvailable = false,
                        FutureUse = false,
                        IsAuthenticData = false,
                        IsCheckingDisabled = false,
                        ResponseCode = DnsResponseCode.NoError,
                        Queries = new[]
                                      {
                                          new DnsQueryResourceRecord(new DnsDomainName("duzce.edu.tr"),//pcapdot.net
                                                                     DnsType.A,
                                                                     DnsClass.Internet),
                                      },
                        Answers = null,
                        Authorities = null,
                        Additionals = null,
                        DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
                    };


            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer,udpLayer, dnsLayer);

            return Tuple.Create(builder.Build(DateTime.Now), ID);
        }






        static void Yorumla(ushort ID) //Interprets the recieved package
        {
            Thread.Sleep(2000); 
            Packet p; 

            try 
            {
                lock (Cevaplar) //Locked because its a critical section
                {
                    p = Cevaplar[ID];
                    Console.WriteLine("mesaj geldi");
                }
            }
            catch
            {
                Console.WriteLine("ZAMAN ASIMI!");
                return;
            }
            DateTime almazamani = p.Timestamp;

            IpV4Datagram ip = p.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            DnsDatagram dns = udp.Dns;
            string sonuc = dns.ToHexadecimalString();
            Console.WriteLine(ip.Source.ToString() + " adresinden gonderilen paketteki DNS bolumu: " + sonuc);
            string dnsString = sonuc.Substring(sonuc.Length - 8, 8);
            Console.WriteLine("DNS'de bulunan cevabın Hexadecimal konumu: " + dnsString);
            string dns_p1= dnsString.Substring(0,2);
            string dns_p2= dnsString.Substring(2,2);
            string dns_p3= dnsString.Substring(4,2);
            string dns_p4= dnsString.Substring(6,2);
            //Console.WriteLine(dns_p1 + dns_p2 + dns_p3 + dns_p4);
            Console.Write(ip.Source.ToString() + " adresinden gelen cevap: ");
            Console.Write(ushort.Parse(dns_p1, System.Globalization.NumberStyles.HexNumber));
            Console.Write(".");
            Console.Write(ushort.Parse(dns_p2, System.Globalization.NumberStyles.HexNumber));
            Console.Write(".");
            Console.Write(ushort.Parse(dns_p3, System.Globalization.NumberStyles.HexNumber));
            Console.Write(".");
            Console.Write(ushort.Parse(dns_p4, System.Globalization.NumberStyles.HexNumber));

        }
    }
}
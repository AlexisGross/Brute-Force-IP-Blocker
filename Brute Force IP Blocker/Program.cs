using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;

namespace Brute_Force_IP_Blocker
{
    internal class Program
    {
        static void Main(string[] args)
        {
            List<string> IPs = ReadSecurityEvents();
            if (IPs.Count > 0)
            {
                Console.WriteLine("Se han detectado intentos de inicio de sesión fallidos provenientes de las siguientes IPs:");
                for (int index = 0; index < IPs.Count; index++)
                {
                    Console.WriteLine(IPs[index]);
                }
                Console.WriteLine("\nTotal de IPs infractoras: " + IPs.Count);
                try
                {
                    Console.WriteLine("Total de IPs bloqueadas actualmente: " + GetIPBloqued().RemoteAddresses.Length);
                }
                catch
                {

                }
                Console.WriteLine("\n¿Desea ejecutar la aplicacion en modo bloqueo continuo?");
                Console.WriteLine("[S] Si [N] No");
                ConsoleKey consoleKey = Console.ReadKey().Key;
                if (consoleKey == ConsoleKey.S)
                {

                }
                else if (consoleKey == ConsoleKey.N)
                {
                    Console.WriteLine("\n¿Desea bloquear estas IPs en el Firewall de Windows Defender?");
                    Console.WriteLine("[S] Si [N] No");
                    consoleKey = Console.ReadKey().Key;
                    if (consoleKey == ConsoleKey.S)
                    {
                        BlockIPs(IPs, GetIPBloqued());
                        // pregunto al usuario si desea vaciar el registro de Windows
                        Console.WriteLine("\n\n¿Desea eliminar todos los registros de seguridad?");
                        Console.WriteLine("[S] Si [N] No");
                        consoleKey = Console.ReadKey().Key;
                        if (consoleKey == ConsoleKey.S)
                        {
                            DeleteSecurityEvents();
                        }
                        else if (consoleKey == ConsoleKey.N)
                        {
                            Console.WriteLine("\nNo se ha eliminado ningun registro de seguridad");
                        }
                        else
                        {

                        }
                    }
                    else if (consoleKey == ConsoleKey.N)
                    {
                        Console.WriteLine("\nNo se ha bloqueado ninguna IP");
                    }
                    else
                    {

                    }
                }
            }
            else
            {
                Console.WriteLine("No se han detectado inicio de sesión fallidos.");
            }
            Console.WriteLine("");
            Console.WriteLine("Precione cualquier tecla para continuar...");
            Console.ReadKey();
        }

        // Creo un metodo que permite leer los eventos de seguridad de Windows
        public static List<string> ReadSecurityEvents()
        {
            // Creo una variable de tipo EventLog
            EventLog eventLog = new EventLog();

            // Le digo que el nombre del evento de seguridad es "Security"
            eventLog.Log = "Security";
            eventLog.Source = "Security";
            // Creo una variable de tipo EventLogEntryCollection
            EventLogEntryCollection eventLogEntryCollection = eventLog.Entries;

            // Creo una variable de tipo EventLogEntryCollection que almacena los eventos de interés
            List<string> eventLogEntryCollectionBadLogIn = new List<string>();

            // Recorro la coleccion de eventos de seguridad
            for (int index = 0; index < eventLogEntryCollection.Count; index++)
            {
                if (eventLogEntryCollection[index].Message.Contains("%%2313"))
                {
                    int StartIn = eventLogEntryCollection[index].Message.IndexOf("Dirección de red de origen:") + 28;
                    int EndIn = eventLogEntryCollection[index].Message.IndexOf("Puerto de origen:") - StartIn - 3;
                    string IP = eventLogEntryCollection[index].Message.Substring(StartIn, EndIn);
                    bool Encontrado = false;
                    foreach (string IPs in eventLogEntryCollectionBadLogIn)
                    {
                        if (IPs == IP)
                        {
                            Encontrado = true;
                        }
                    }
                    if (!Encontrado)
                    {
                        eventLogEntryCollectionBadLogIn.Add(IP);
                    }
                }
            }
            return eventLogEntryCollectionBadLogIn;
        }

        // Creo un metodo que permite bloquear las IPs en el Firewall de Windows Defender
        public static void BlockIPs(List<string> IPs, IFirewallRule firewallRule)
        {
            int Tamaño = firewallRule.RemoteAddresses.Length;
            Tamaño += IPs.Count;
            SingleIP[] Addresses = new SingleIP[Tamaño];
            int index = 0;
            for (index = 0; index < firewallRule.RemoteAddresses.Length; index++)
            {
                Addresses[index] = (SingleIP)firewallRule.RemoteAddresses[index];
            }
            for (int index1 = 0; index1 < IPs.Count; index1++)
            {
                Addresses[index] = SingleIP.Parse(IPs[index1]);
                index++;
            }
            
            if (firewallRule != null)
            {
                // Actualiza la regla
                firewallRule.RemoteAddresses = Addresses;
            }
            else
            {
                // Crea una nueva regla
                firewallRule = FirewallManager.Instance.CreateApplicationRule(FirewallManager.Instance.GetProfile(FirewallProfiles.Private).Type, @"Bloqueador IP", FirewallAction.Allow, null);
                firewallRule.Direction = FirewallDirection.Inbound;
                firewallRule.Action = FirewallAction.Block;
                firewallRule.Protocol = FirewallProtocol.TCP;
                firewallRule.Scope = FirewallScope.Specific;
                firewallRule.RemoteAddresses = (IAddress[])Addresses;

                FirewallManager.Instance.Rules.Add(firewallRule);

                Console.WriteLine("Se han bloqueado las IPs en el Firewall de Windows Defender.");
            }
        }
        
        private static void DeleteSecurityEvents()
        {
            EventLog.Delete("Microsoft-Windows-Security-Auditing");
        }

        private static IFirewallRule GetIPBloqued()
        {
            return FirewallManager.Instance.Rules.FirstOrDefault(o => o.Direction == FirewallDirection.Inbound && o.Name.Equals("Bloqueador IP"));
        }
    }
}
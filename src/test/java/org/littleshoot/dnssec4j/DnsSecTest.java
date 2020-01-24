package org.littleshoot.dnssec4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.DatagramChannel;
import java.util.Arrays;
import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test for DNSSEC lookups.
 */
public class DnsSecTest {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
    @Test
    public void testVerify() throws Exception {
        final InetSocketAddress base = new InetSocketAddress("www.brown.edu", 80);
        final InetAddress ia = base.getAddress();
        final String resolved = ia.getHostAddress();
        
        final InetSocketAddress unresolved =
            InetSocketAddress.createUnresolved("www.brown.edu", 80);
        final InetSocketAddress verified = DnsSec.verify(unresolved);
        
        final String resolvedAndVerified = verified.getAddress().getHostAddress();
        assertEquals(resolved, resolvedAndVerified);
    }
    
    @Test
    public void testGetByName() throws Exception {
        final Collection<String> hosts = Arrays.asList("www.verisign.com",
            "nlnet.nl", "www.beck.com", "www.wikipedia.org",
            "smartfil.es", "www.asperasoft.com", "www.brown.edu");
            //"www.root-dnssec.org", "www.dnssec.org", "www.opendnssec.org");
         
        for (final String host : hosts) {
            System.out.println("\n****************************************");
            System.out.println("      TESTING "+host);
            System.out.println("****************************************");
            final InetAddress ia = DnsSec.getByName(host);
            System.out.println("\n****************************************");
            System.out.println("  DONE TESTING "+host);
            System.out.println("****************************************");
            assertNotNull(ia, "Did not get address");
            final InetAddress standard = InetAddress.getByName(host);
            assertEquals(ia.getHostAddress(), standard.getHostAddress(), "Results not equal for "+host);
            final DatagramChannel channel = DatagramChannel.open();
            final SocketAddress server = new InetSocketAddress(host, 80);
            channel.connect(server);
            assertTrue(channel.isConnected(), "Could not connect to host "+host);
            //return;
        }
        
        // These domains give back different responses to different queries --
        // so we cannot check for equality. We just make sure the addresses
        // we get back are reachable.
        final Collection<String> varyingResultHosts = Arrays.asList(
            "www.google.com", "www.littleshoot.org", "www.reddit.com",
            "adamfisk.wordpress.com", "www.bittorrent.com",
            "www.comcast.net");
        
        for (final String host : varyingResultHosts) {
            System.out.println("\n****************************************");
            System.out.println("      TESTING "+host);
            System.out.println("****************************************");
            final InetAddress ia = DnsSec.getByName(host);
            System.out.println("\n****************************************");
            System.out.println("  DONE TESTING "+host);
            System.out.println("****************************************");
            assertNotNull(ia, "Did not get address");
            
            final DatagramChannel channel = DatagramChannel.open();
            final SocketAddress server = new InetSocketAddress(host, 80);
            channel.connect(server);
            assertTrue(channel.isConnected(), "Could not connect to host "+host);
        }
    }
}

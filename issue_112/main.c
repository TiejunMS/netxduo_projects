/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include   "nx_secure_tls_api.h"
#include   "nxd_dhcp_client.h"
#include   "nxd_dns.h"
#include   "cert.h"

#define SAMPLE_IPV4_ADDRESS     IP_ADDRESS(0, 0, 0, 0)
#define SAMPLE_IPV4_MASK        0xFFFFFFFFUL
#define SAMPLE_SERVER_DOMAIN    "github.com"

#define PRINT_IP(d, i)          printf(d ": %lu.%lu.%lu.%lu\r\n", \
                                       ((i) >> 24), \
                                       ((i) >> 16 & 0xFF), \
                                       ((i) >> 8 & 0xFF), \
                                       ((i) & 0xFF))

#ifndef SAMPLE_DHCP_WAIT_OPTION
#define SAMPLE_DHCP_WAIT_OPTION (20 * NX_IP_PERIODIC_RATE)
#endif /* SAMPLE_DHCP_WAIT_OPTION */

#ifndef SAMPLE_DNS_WAIT_OPTION
#define SAMPLE_DNS_WAIT_OPTION  (20 * NX_IP_PERIODIC_RATE)
#endif /* SAMPLE_DNS_WAIT_OPTION */

#define NUM_PACKETS             128
#define PACKET_SIZE             1536
#define PACKET_POOL_SIZE        (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE       1024
#define ARP_CACHE_SIZE          1024
#define BUFFER_SIZE             17000
#define METADATA_SIZE           16000
#define CERT_BUFFER_SIZE        4096
#define PACKET_BUFFER_SIZE      40960
#define SERVER_PORT             443
#define IP_THREAD_PRIORITY      1
#define THREAD_PRIORITY         4

static TX_THREAD                thread_0;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static NX_DNS                   dns_0;
static NX_DHCP                  dhcp_0;
static UINT                     error_counter;
static UINT                     total_bytes;

static NX_TCP_SOCKET            client_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      client_trusted_ca;
static UCHAR                    tls_packet_buffer[PACKET_BUFFER_SIZE];
static UCHAR                    receive_buffer[BUFFER_SIZE];

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;
extern const                    NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

static VOID  thread_0_entry(ULONG thread_input);
extern VOID  _nx_linux_network_driver(NX_IP_DRIVER*);

static VOID    ERROR_COUNTER()
{
    error_counter++;
    printf("ERROR\r\n");
    for(;;);
}

/* Define main entry point.  */
int main()
{

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}


/* Define what the initial system looks like.  */
void    tx_application_define(void *first_unused_memory)
{

UINT    status;

    NX_PARAMETER_NOT_USED(first_unused_memory);

    srand(time(0));

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool",
                                   PACKET_SIZE, pool_0_memory, sizeof(pool_0_memory));

    /* Check for packet pool create errors.  */
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", SAMPLE_IPV4_ADDRESS, SAMPLE_IPV4_MASK,
                          &pool_0, _nx_linux_network_driver,
                          (void *)ip_0_stack, sizeof(ip_0_stack), IP_THREAD_PRIORITY);

    /* Check for IP create errors.  */
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)arp_cache, sizeof(arp_cache));

    /* Check for ARP enable errors.  */
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ICMP */
    status = nx_icmp_enable(&ip_0);

    /* Check for ICMP enable errors.  */
    if(status)
    {
        ERROR_COUNTER();
    }

    /* Enable TCP for IP Instance 0.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check for TCP enable errors.  */
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable UDP for IP Instance 0.  */
    status =  nx_udp_enable(&ip_0);

    /* Check for UDP enable errors.  */
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Initialize TLS.  */
    nx_secure_tls_initialize();

    /* Create the server thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     THREAD_PRIORITY, THREAD_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers_ecc,
                                          client_metadata,
                                          sizeof(client_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    // memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    // status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
    //                                                    &client_remote_cert,
    //                                                    client_cert_buffer,
    //                                                    sizeof(client_cert_buffer));
    // if (status)
    // {
    //     ERROR_COUNTER();
    // }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, DigiCertGlobalRootCA_crt, DigiCertGlobalRootCA_crt_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer,
                                                     sizeof(tls_packet_buffer));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static UINT dns_create(ULONG dns_server_address)
{
UINT    status;

    /* Create a DNS instance for the Client.  Note this function will create
       the DNS Client packet pool for creating DNS message packets intended
       for querying its DNS server.  */
    status = nx_dns_create(&dns_0, &ip_0, (UCHAR *)"DNS Client");
    if (status)
    {
        return(status);
    }

    /* Is the DNS client configured for the host application to create the packet pool?  */
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL

    /* Yes, use the packet pool created above which has appropriate payload size
       for DNS messages.  */
    status = nx_dns_packet_pool_set(&dns_0, ip_0.nx_ip_default_packet_pool);
    if (status)
    {
        nx_dns_delete(&dns_0);
        return(status);
    }
#endif /* NX_DNS_CLIENT_USER_CREATE_PACKET_POOL */

    /* Add an IPv4 server address to the Client list.  */
    status = nx_dns_server_add(&dns_0, dns_server_address);
    if (status)
    {
        nx_dns_delete(&dns_0);
        return(status);
    }

    /* Output DNS Server address.  */
    PRINT_IP("DNS Server address", dns_server_address);

    return(NX_SUCCESS);
}

static UINT dhcp_wait()
{
UINT    status;
ULONG   actual_status;

    printf("DHCP In Progress...\r\n");

    /* Create the DHCP instance.  */
    status = nx_dhcp_create(&dhcp_0, &ip_0, "DHCP Client");

    /* Check status.  */
    if (status)
    {
        return(status);
    }

    /* Request NTP server.  */
    status = nx_dhcp_user_option_request(&dhcp_0, NX_DHCP_OPTION_NTP_SVR);

    /* Check status.  */
    if (status)
    {
        nx_dhcp_delete(&dhcp_0);
        return(status);
    }

    /* Start the DHCP Client.  */
    status = nx_dhcp_start(&dhcp_0);

    /* Check status.  */
    if (status)
    {
        nx_dhcp_delete(&dhcp_0);
        return(status);
    }

    /* Wait util address is solved.  */
    status = nx_ip_status_check(&ip_0, NX_IP_ADDRESS_RESOLVED, &actual_status, SAMPLE_DHCP_WAIT_OPTION);

    /* Check status.  */
    if (status)
    {
        nx_dhcp_delete(&dhcp_0);
        return(status);
    }

    return(NX_SUCCESS);
}

static void thread_0_entry(ULONG thread_input)
{
UINT status;
ULONG ip_address = 0;
ULONG network_mask = 0;
ULONG gateway_address = 0;
UINT unix_time;
ULONG dns_server_address[3];
UINT dns_server_address_size = sizeof(dns_server_address);
UINT server_address_size = sizeof(ULONG);
ULONG bytes_copied;
NX_PACKET *packet_ptr = NX_NULL;
NXD_ADDRESS server_address;
NX_PACKET *packet_ptr_s = NULL;
UINT pos_in_packet;
ULONG receive_size_max = 17000;

    if (dhcp_wait())
    {
        ERROR_COUNTER();
    }

    /* Get IP address and gateway address.  */
    nx_ip_address_get(&ip_0, &ip_address, &network_mask);
    nx_ip_gateway_address_get(&ip_0, &gateway_address);

    /* Output IP address and gateway address.  */
    PRINT_IP("IP address", ip_address);
    PRINT_IP("Mask", network_mask);
    PRINT_IP("Gateway", gateway_address);

    /* Retrieve DNS server address.  */
    nx_dhcp_interface_user_option_retrieve(&dhcp_0, 0, NX_DHCP_OPTION_DNS_SVR, (UCHAR *)(dns_server_address),
                                           &dns_server_address_size);

    /* Create DNS.  */
    status = dns_create(dns_server_address[0]);

    /* Check for DNS create errors.  */
    if (status)
    {
        ERROR_COUNTER();
        return;
    }

    /* Look up Server address. */
    printf("Resolving hostname: " SAMPLE_SERVER_DOMAIN "\r\n");
    status = nx_dns_host_by_name_get(&dns_0, SAMPLE_SERVER_DOMAIN, &server_address.nxd_ip_address.v4, SAMPLE_DNS_WAIT_OPTION);
    if (status)
    {
        ERROR_COUNTER();
        return;
    }
    PRINT_IP("IP address of " SAMPLE_SERVER_DOMAIN ": ", server_address.nxd_ip_address.v4);

    server_address.nxd_ip_version = NX_IP_VERSION_V4;

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_tls_setup(&tls_client_session_0);

    status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                            NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    printf("TCP connection established\r\n");

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0,
                                          NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    printf("TLS session established\r\n");

    /* Loop to echo data.  */
    for (;;)
    {
        
        /* Wait for a packet.  */
        if (!packet_ptr)
        {
            status = nx_secure_tls_session_receive(&tls_client_session_0, &packet_ptr, NX_WAIT_FOREVER);
            if (status)
            {
                ERROR_COUNTER();
                break;
            }
            total_bytes += packet_ptr->nx_packet_length;
            printf("Received packet: %05lu bytes, total %07u bytes\r\n", packet_ptr->nx_packet_length, total_bytes);

            pos_in_packet = 0;
        }

        /* Extract the data from the packet.  */
        ULONG remain = packet_ptr->nx_packet_length - pos_in_packet;
        ULONG length = (remain < receive_size_max) ? remain : receive_size_max;
        status = nx_packet_data_extract_offset(packet_ptr, pos_in_packet, receive_buffer,
                                               length, &bytes_copied);
        if (status)
        {
            ERROR_COUNTER();
            nx_packet_release(packet_ptr);
            break;
        }
        pos_in_packet += bytes_copied;
        printf("Data copied: %05lu bytes, pos in packet: %05u\r\n", bytes_copied, pos_in_packet);

        /* Release received packet.  */
        if (packet_ptr->nx_packet_length <= pos_in_packet)
        {
            nx_packet_release(packet_ptr);
            packet_ptr = NULL;
            pos_in_packet = 0;
            printf("Packet released (pos in packet %05u)\r\n", pos_in_packet);
        }

        /* Allocate a TLS packet for transmission.  */
        status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_0,
                                               &packet_ptr_s, NX_WAIT_FOREVER);
        printf("Packet allocated\r\n");
        if (status)
        {
            ERROR_COUNTER();
            break;
        }

        /* Append data to the packet.  */
        status = nx_packet_data_append(packet_ptr_s, receive_buffer, bytes_copied, &pool_0,
                                       NX_WAIT_FOREVER);
        printf("Data appended %05lu\r\n", bytes_copied);
        if (status)
        {
            ERROR_COUNTER();
            nx_packet_release(packet_ptr_s);
            break;
        }

        /* Send the data back to the server.  */
        status = nx_secure_tls_session_send(&tls_client_session_0, packet_ptr_s, NX_WAIT_FOREVER);
        printf("Data sent\r\n");
        if (status)
        {
            ERROR_COUNTER();
            nx_packet_release(packet_ptr_s);
            break;
        }
    }

    nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
    nx_secure_tls_session_delete(&tls_client_session_0);
    nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);
}
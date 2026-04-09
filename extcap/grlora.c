/* grlora.c
 * grlora is an extcap tool used for bridge GNU Radio with LoRa capture to Wireshark
 *
 * Copyright 2026, Kevin Leon <kevinleon.morales@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "grlora"

#include <extcap/extcap-base.h>

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TIME_H
	#include <sys/time.h>
#endif

#ifdef HAVE_NETINET_IN_H
	#include <netinet/in.h>
#endif

#include <string.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
	#include <unistd.h>
#endif

#include <writecap/pcapio.h>
#include <wiretap/wtap.h>
#include <wsutil/strtoi.h>
#include <wsutil/inet_addr.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/socket.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/wslog.h>
#include <wsutil/pint.h>
#include <wsutil/exported_pdu_tlvs.h>
#include <app/application_flavor.h>

#include <cli_main.h>

#define PCAP_SNAPLEN 0xffff

#define GRLORA_DEFAULT_HOST           "0.0.0.0"
#define GRLORA_DEFAULT_HOST_PORT      5009
#define GRLORA_DEFAULT_REMOTE         "0.0.0.0"
#define GRLORA_DEFAULT_REMOTE_PORT    5008
#define GRLORA_DEFAULT_FREQUENCY      916
#define GRLORA_DEFAULT_BANDWIDTH      250
#define GRLORA_DEFAULT_SPREAD_FACTOR  7

#define GRLORA_EXTCAP_INTERFACE "grlora"
#define GRLORA_VERSION_MAJOR "0"
#define GRLORA_VERSION_MINOR "1"
#define GRLORA_VERSION_RELEASE "0"

#define PKT_BUF_SIZE 65535

#define GRLORA_EXPORT_HEADER_LEN 40

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
  OPT_HOST_PORT,
  OPT_REMOTE_HOST,
  OPT_REMOTE_PORT,
	OPT_FREQUENCY, // Center Frequency
	OPT_BANDWIDTH,
  OPT_SPREAD_FACTOR
};

static const struct ws_option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	/* Generic application options */
	{ "help", ws_no_argument, NULL, OPT_HELP},
	{ "version", ws_no_argument, NULL, OPT_VERSION},
	/* Interfaces options */
	{ "port", ws_required_argument, NULL, OPT_HOST_PORT},
  { "remotehost", ws_required_argument, NULL, OPT_REMOTE_HOST},
	{ "remoteport", ws_required_argument, NULL, OPT_REMOTE_PORT},
  { "frequency", ws_required_argument, NULL, OPT_FREQUENCY},
  { "bandwidth", ws_required_argument, NULL, OPT_BANDWIDTH},
  { "spreadfactor", ws_required_argument, NULL, OPT_SPREAD_FACTOR},
  { 0, 0, 0, 0 }
};

static int list_config(char *interface) {
  unsigned inc = 0;
  if (!interface) {
    ws_warning("No interface specified.");
    return EXIT_FAILURE;
  }

  printf("arg {number=%u}{call=--port}{display=Host Server Port RX}"
    "{type=unsigned}{range=1,65535}{default=%u}{tooltip=The port listens on}{group=Server}\n",
    inc++, GRLORA_DEFAULT_HOST_PORT);

  printf("arg {number=%u}{call=--remotehost}{display=Remote GNU Radio Server TX}"
    "{type=string}{default=%s}{tooltip=The host GNU Radio listens on}{group=Server}\n",
    inc++, GRLORA_DEFAULT_REMOTE);

  printf("arg {number=%u}{call=--remoteport}{display=GNU Radio Port TX}"
    "{type=unsigned}{range=1,65535}{default=%u}{tooltip=The port GNU Radio listens on}{group=Server}\n",
    inc++, GRLORA_DEFAULT_REMOTE_PORT);
  
  printf("arg {number=%u}{call=--frequency}{display=GNU Radio Center Frequency (MHz)}"
    "{type=double}{range=70, 960}{default=%u}{tooltip=The Center Frequency}{group=Radio}\n",
    inc++, GRLORA_DEFAULT_FREQUENCY);
  
  printf("arg {number=%u}{call=--bandwidth}{display=GNU Radio Bandwidth (kHz)}"
  "{type=selector}{tooltip=The Bandwidth}{group=Radio}\n", inc);

  unsigned idx_bandwidth = inc;
  inc++;
  printf("arg {number=%u}{call=--spreadfactor}{display=GNU Radio Port}"
  "{type=selector}{tooltip=The Spreading Factor}{group=Radio}\n",
  inc);
  unsigned idx_spreadfactor = inc;
  inc++;

  printf("value {arg=%u}{value=7.8}{display=7.8 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=10.4}{display=10.4 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=15.6}{display=15.6 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=20.8}{display=20.8 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=31.25}{display=31.25 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=41.7}{display=41.7 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=62.5}{display=62.5 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=125}{display=125 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=250}{display=250 KHz}\n", idx_bandwidth);
  printf("value {arg=%u}{value=500}{display=500 KHz}\n", idx_bandwidth);

  for (int i = 6; i < 13; i++) {
    printf("value {arg=%u}{value=%u}{display=%u}\n", idx_spreadfactor, i, i);
  }

  extcap_config_debug(&inc);

  return EXIT_SUCCESS;
}

static int setup_listener(const uint16_t port, socket_handle_t* sock) {
  int optval;
  struct sockaddr_in serveraddr;
#ifndef _WIN32
  struct timeval timeout = { 1, 0 };
#endif
  *sock = socket(AF_INET, SOCK_DGRAM, 0);

  if (*sock == INVALID_SOCKET) {
    ws_warning("Error opening socket: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  optval = 1;
  if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, (socklen_t)sizeof(int)) < 0) {
    ws_warning("Can't set socket option SO_REUSEADDR: %s", strerror(errno));
    goto cleanup_setup_listener;
  }

#ifndef _WIN32
  if (setsockopt (*sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, (socklen_t)sizeof(timeout)) < 0) {
    ws_warning("Can't set socket option SO_RCVTIMEO: %s", strerror(errno));
    goto cleanup_setup_listener;
  }
#endif

  memset(&serveraddr, 0x0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  serveraddr.sin_port = htons(port);

  if (bind(*sock, (struct sockaddr *)&serveraddr, (socklen_t)sizeof(serveraddr)) < 0) {
    ws_warning("Error on binding: %s", strerror(errno));
    goto cleanup_setup_listener;
  }

  return EXIT_SUCCESS;

  cleanup_setup_listener:
    closesocket(*sock);
  return EXIT_FAILURE;

}

static int setup_dumpfile(const char* fifo, ws_cwstream** fp)
{
  uint64_t bytes_written = 0;
  int err;

  if (!g_strcmp0(fifo, "-")) {
    *fp = ws_cwstream_open_stdout(WS_FILE_UNCOMPRESSED, &err);
    if (!(*fp)) {
      ws_warning("Error opening standard out: %s", g_strerror(errno));
      return EXIT_FAILURE;
    }
    /* XXX - Why does this not write the pcap file header to stdout? */
    return EXIT_SUCCESS;
  }

  *fp = ws_cwstream_open(fifo, WS_FILE_UNCOMPRESSED, &err);
  if (!(*fp)) {
    ws_warning("Error creating output file: %s", g_strerror(errno));
    return EXIT_FAILURE;
  }

  if (!libpcap_write_file_header(*fp, 148, PCAP_SNAPLEN, false, &bytes_written, &err)) {
    ws_warning("Can't write pcap file header: %s", g_strerror(err));
    return EXIT_FAILURE;
  }

  ws_cwstream_flush(*fp, &err);

  return EXIT_SUCCESS;
}

static int dump_packet(const char* buf, const ssize_t buflen, ws_cwstream* fp)
{
  uint8_t* mbuf;
  unsigned offset = 0;
  int64_t curtime = g_get_real_time();
  uint64_t bytes_written = 0;
  int err;
  int ret = EXIT_SUCCESS;

  mbuf = (uint8_t*)g_malloc0(buflen);

  memcpy(mbuf + offset, buf, buflen);
  offset += (unsigned)buflen;

  if (!libpcap_write_packet(fp,
      (uint32_t)(curtime / G_USEC_PER_SEC), (uint32_t)(curtime % G_USEC_PER_SEC),
      offset, offset, mbuf, &bytes_written, &err)) {
    ws_warning("Can't write packet: %s", g_strerror(err));
    ret = EXIT_FAILURE;
      }

  ws_cwstream_flush(fp, &err);

  g_free(mbuf);
  return ret;
}

static void run_listener(const char* fifo, const uint16_t  gradio_host_port, const char* gradio_host, const uint16_t  gradio_remote_port,
      const uint16_t gradio_frequency, const uint16_t gradio_bandwidth, const uint16_t gradio_spreadfactor) {
  struct sockaddr_in clientaddr;
  socklen_t clientlen = sizeof(clientaddr);
  socket_handle_t sock;
  char* buf;
  ssize_t buflen;
  ws_cwstream* fp = NULL;

  if (setup_dumpfile(fifo, &fp) == EXIT_FAILURE) {
    if (fp)
      ws_cwstream_close(fp, NULL);
    return;
  }

  if (setup_listener(gradio_host_port, &sock) == EXIT_FAILURE) { return; }

  ws_debug("Listener running on port %u", gradio_host_port);
  buf = (char*)g_malloc(PKT_BUF_SIZE);
  while (!extcap_end_application) {
    memset(buf, 0x0, PKT_BUF_SIZE);

    buflen = recvfrom(sock, buf, PKT_BUF_SIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
    if (buflen < 0) {
      switch (errno) {
        case EAGAIN:
        case EINTR:
          break;
        default:
#ifdef _WIN32
        {
          wchar_t *errmsg = NULL;
          int err = WSAGetLastError();
          FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&errmsg, 0, NULL);
          ws_warning("Error in recvfrom: %S (err=%d)", errmsg, err);
          LocalFree(errmsg);
        }
#else
          ws_warning("Error in recvfrom: %s (errno=%d)", strerror(errno), errno);
#endif
          extcap_end_application = true;
          break;
      }
    }else {
      if (dump_packet(buf, buflen, fp) == EXIT_FAILURE) {
        extcap_end_application = true;
      }
    }
  }
  ws_cwstream_close(fp, NULL);
  closesocket(sock);
  g_free(buf);
}

int main(int argc, char *argv[]){
  char* err_msg;
  int option_idx = 0;
  int result;
  int ret = EXIT_FAILURE;
  extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
  char* help_url;
	char* help_header = NULL;
	char* generic_msg = NULL;
  // GRadio
  char* gradio_host = NULL;
  uint16_t gradio_host_port = GRLORA_DEFAULT_HOST_PORT;
  uint16_t gradio_remote_port = GRLORA_DEFAULT_REMOTE_PORT;
  double gradio_frequency = GRLORA_DEFAULT_FREQUENCY;
  double gradio_bandwidth = GRLORA_DEFAULT_BANDWIDTH;
  uint16_t gradio_spreadfactor = GRLORA_DEFAULT_SPREAD_FACTOR;

  /* Set the program name. */
  g_set_prgname("grlora");

  /* Initialize log handler early so we can have proper logging during startup. */
	extcap_log_init();

  init_process_policies();

  // err_msg = configuration_init(argv[0], "grlorashark");
  err_msg = configuration_init(argv[0], "wireshark");
  if (err_msg != NULL){
    ws_warning("Cant't get pathname of directory containing the extcap program: %s", err_msg);
    g_free(err_msg);
  }

  help_url = data_file_url("grlora.html", application_configuration_environment_prefix());
  extcap_base_set_util_info(extcap_conf, argv[0], GRLORA_VERSION_MAJOR, GRLORA_VERSION_MINOR, GRLORA_VERSION_RELEASE, help_url);
  g_free(help_url);
  extcap_base_register_interface(extcap_conf, GRLORA_EXTCAP_INTERFACE, "GNU Radio bridge", 148, "LoRa communication bridge");

  help_header = ws_strdup_printf(
    " %s --extcap-interfaces\n"
    " %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --port 50009 --fifo myfifo --capture",
    argv[0], argv[0], GRLORA_EXTCAP_INTERFACE, argv[0], GRLORA_EXTCAP_INTERFACE, argv[0], GRLORA_EXTCAP_INTERFACE);
  extcap_help_add_header(extcap_conf, help_header);
  g_free(help_header);
  extcap_help_add_option(extcap_conf, "--help", "print this help");
  extcap_help_add_option(extcap_conf, "--version", "print the version");

  generic_msg = ws_strdup_printf("the port GNU Radio listens on. Default: %u", GRLORA_DEFAULT_HOST_PORT);
  extcap_help_add_option(extcap_conf, "--port <port>", generic_msg);
  g_free(generic_msg);

  generic_msg = ws_strdup_printf("the GNU Radio host listens on. Default: %s", GRLORA_DEFAULT_REMOTE);
  extcap_help_add_option(extcap_conf, "--remotehost <remotehost>", generic_msg);
  g_free(generic_msg);

  generic_msg = ws_strdup_printf("the port GNU Radio listens on. Default: %u", GRLORA_DEFAULT_REMOTE_PORT);
  extcap_help_add_option(extcap_conf, "--remoteport <remoteport>", generic_msg);
  g_free(generic_msg);

  generic_msg = ws_strdup_printf("the frequency GNU Radio listens on. Default: %u", GRLORA_DEFAULT_FREQUENCY);
  extcap_help_add_option(extcap_conf, "--frequency <frequency>", generic_msg);
  g_free(generic_msg);

  generic_msg = ws_strdup_printf("the bandwidth GNU Radio listens on. Default: %u", GRLORA_DEFAULT_BANDWIDTH);
  extcap_help_add_option(extcap_conf, "--bandwidth <bandwidth>", generic_msg);
  g_free(generic_msg);

  generic_msg = ws_strdup_printf("the spread factor GNU Radio listens on. Default: %u", GRLORA_DEFAULT_SPREAD_FACTOR);
  extcap_help_add_option(extcap_conf, "--spreadfactor <spreadfactor>", generic_msg);
  g_free(generic_msg);

  ws_opterr = 0;
  ws_optind = 0;

  if (argc == 1){
    extcap_help_print(extcap_conf);
    goto end;
  }

  while ((result = ws_getopt_long(argc, argv, ":", longopts, &option_idx)) != -1){
    switch (result)
    {
    case OPT_HELP:
      extcap_help_print(extcap_conf);
      ret = EXIT_SUCCESS;
      goto end;
    case OPT_VERSION:
      extcap_version_print(extcap_conf);
      ret = EXIT_SUCCESS;
      goto end;
    case OPT_HOST_PORT:
      if (!ws_strtou16(ws_optarg, NULL, &gradio_host_port)) {
				ws_warning("Invalid port: %s", ws_optarg);
				goto end;
			}
			break;
    case OPT_REMOTE_HOST:
      g_free(gradio_host);
      gradio_host = g_strdup(ws_optarg);
      break;
    case OPT_REMOTE_PORT:
      if (!ws_strtou16(ws_optarg, NULL, &gradio_remote_port)) {
				ws_warning("Invalid port: %s", ws_optarg);
				goto end;
			}
			break;
    case OPT_FREQUENCY:
      char *endptrfreq = NULL;
      gradio_frequency = g_ascii_strtod(ws_optarg, &endptrfreq);

      if (endptrfreq == ws_optarg || errno == ERANGE) {
        ws_warning("Invalid frequency: %s", ws_optarg);
        goto end;
      }
			break;
    case OPT_BANDWIDTH:
      char *endptrbw = NULL;
      gradio_bandwidth = g_ascii_strtod(ws_optarg, &endptrbw);

      if (endptrbw == ws_optarg || errno == ERANGE) {
        ws_warning("Invalid bandwidth: %s", ws_optarg);
        goto end;
      }
			break;
    case OPT_SPREAD_FACTOR:
      if (!ws_strtou16(ws_optarg, NULL, &gradio_spreadfactor)) {
				ws_warning("Invalid spread factor: %s", ws_optarg);
				goto end;
			}
			break;
    case ':':
      /* missing option argument */
      ws_warning("Option '%s' requieres an argument", argv[ws_optind - 1]);
      break;
    default:
      if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, ws_optarg)) {
        ws_warning("Invalid options: %s", argv[ws_optind - 1]);
        goto end;
      }
    }
  }

  extcap_cmdline_debug(argv, argc);

  if (ws_optind != argc){
    ws_warning("Unexpected extra option: %s", argv[ws_optind]);
    goto end;
  }

  if (extcap_base_handle_interface(extcap_conf)){
    ret = EXIT_SUCCESS;
    goto end;
  }

  if (!extcap_base_register_graceful_shutdown_cb(extcap_conf, NULL)){
    ret = EXIT_SUCCESS;
    goto end;
  }

  if (extcap_conf->show_config){
    ret = list_config(extcap_conf->interface);
    goto end;
  }

  if (!gradio_host){
    gradio_host = g_strdup(GRLORA_DEFAULT_REMOTE);
  }

  err_msg = ws_init_sockets();
	if (err_msg != NULL) {
		ws_warning("Error: %s", err_msg);
		g_free(err_msg);
		ws_warning("%s", please_report_bug());
		goto end;
	}

  if (gradio_host_port == 0){ gradio_host_port = GRLORA_DEFAULT_HOST_PORT;}
  if (gradio_remote_port == 0){ gradio_remote_port = GRLORA_DEFAULT_REMOTE_PORT;}
  if (gradio_frequency == 0){ gradio_frequency = GRLORA_DEFAULT_FREQUENCY;}
  if (gradio_bandwidth == 0){ gradio_bandwidth = GRLORA_DEFAULT_BANDWIDTH;}
  if (gradio_spreadfactor == 0){ gradio_spreadfactor = GRLORA_DEFAULT_SPREAD_FACTOR;}

  if (extcap_conf->capture) {
    run_listener(extcap_conf->fifo, gradio_host_port, gradio_host, gradio_remote_port,
      gradio_frequency, gradio_bandwidth, gradio_spreadfactor);
  }

end:
  /* Clean up stuff */
  extcap_base_cleanup(&extcap_conf);
  g_free(gradio_host);
  return ret;
}
#include "sniffer.h"

#define MAX_PACKETS 999

int main(int argc, char *argv[]) {

  char filter_exp[50], device[10], packet_num_str[5], file_name[30];
  int packet_num = 0;

  initscr();

  WINDOW *info_win = newwin(21, 80, 0, 0);
  refresh();
  box(info_win, 0, 0);
  wrefresh(info_win);

  /* Device window */
  WINDOW *dev_win = newwin(3, 20, 21, 0);
  refresh();
  mvwprintw(dev_win, 1, 1, "Device: ");
  wrefresh(dev_win);
  mvwscanw(dev_win, 2, 1, "%s", device);

  /* Filter expression window */
  WINDOW *filter_win = newwin(3, 20, 21, 20);
  refresh();
  mvwprintw(filter_win, 1, 1, "Filter: ");
  wrefresh(filter_win);
  mvwscanw(filter_win, 2, 1, "%s", filter_exp);

  /* Packets to capture number window */
  WINDOW *packets_win = newwin(3, 20, 21, 40);
  refresh();
  mvwprintw(packets_win, 1, 1, "Packet num: ");
  wrefresh(packets_win);
  mvwscanw(packets_win, 2, 1, "%s", packet_num_str);
  packet_num = atoi(packet_num_str);

  /* Process invalid input */
  if (packet_num > MAX_PACKETS) {
    packet_num = MAX_PACKETS;
  } else if (packet_num < 0) {
    packet_num = 0;
  }
  wclear(packets_win);
  mvwprintw(packets_win, 1, 1, "Packet num:");
  mvwprintw(packets_win, 2, 1, "%d", packet_num);
  wrefresh(packets_win);

  /* File window */
  WINDOW *file_win = newwin(3, 20, 21, 60);
  refresh();
  mvwprintw(file_win, 1, 1, "File: ");
  wrefresh(file_win);
  mvwscanw(file_win, 2, 1, "%s", file_name);

  curs_set(0);

  // mvwprintw(info_win, 1, 1, "%s   %s  %d", device, filter_exp, packet_num);
  // wrefresh(info_win);




  // sniffer(filter_exp, device, num_packets);

  getch();
  endwin();

  return 0;
}

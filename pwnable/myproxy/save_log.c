void SaveLog(int fd, char *s, int a3) {
  size_t v3; // eax@6
  size_t v4; // eax@7
  socklen_t len; // [sp+1Ch] [bp-1Ch]@3
  struct sockaddr addr; // [sp+20h] [bp-18h]@3
  struct_log_link *entry; // [sp+30h] [bp-8h]@7
  struct_log_link *ptr; // [sp+34h] [bp-4h]@2

  if ( nlog == 32 )
  {
    ptr = log_head->prev;
    ptr->prev->next = ptr->next;
    ptr->next->prev = ptr->prev;
    free(ptr);
    --nlog;
  }
  len = 16;
  if ( getpeername(fd, &addr, &len) == -1 )
  {
    perror("getpeername() failed");
  }
  else if ( log_head )
  {
    entry = malloc(0x88u);
    memset(entry, 0, 0x88u);
    entry->addr = *&addr.sa_data[2];
    entry->port = a3;
    entry->next = log_head;
    entry->prev = log_head->prev;
    v4 = strlen(s);
    strncpy(entry->host, s, v4);
    log_head->prev->next = entry;
    log_head->prev = entry;
    log_head = entry;
    ++nlog;
  }
  else
  {
    log_head = malloc(0x88u);
    memset(log_head, 0, 0x88u);
    v3 = strlen(s);
    strncpy(log_head->host, s, v3);
    log_head->addr = *&addr.sa_data[2];
    log_head->port = a3;
    log_head->next = log_head;
    log_head->prev = log_head;
    ++nlog;
  }
}
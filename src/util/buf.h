typedef struct {
  uint8_t *c;
  size_t len;
  size_t cap;
}  tls_buf;

void tls_buf_init(tls_buf* t);
int tls_buf_copy_string(tls_buf* t, const char * str);
uint8_t tls_buf_get(const tls_buf* t, size_t index);
int tls_buf_set(tls_buf* t, size_t index, uint8_t value);
int tls_buf_clone(tls_buf *dst, const tls_buf* src);
int tls_buf_append(tls_buf *dst, const tls_buf* src);
int tls_buf_copy(tls_buf *dst, const tls_buf* src, size_t dst_off,
                     size_t src_off, size_t len);
void tls_buf_clean(tls_buf *t);
size_t tls_buf_len(const tls_buf *t);
int tls_buf_ensure_cap(tls_buf *t, size_t cap);

import urllib.parse

class CaseInsensitiveDict(dict):
    def __init__(self, data=None):
        super().__init__()
        if data:
            for k, v in data.items():
                self[k] = v

    def __setitem__(self, key, value):
        super().__setitem__(str(key).lower(), value)

    def __getitem__(self, key):
        return super().__getitem__(str(key).lower())

    def __contains__(self, key):
        return super().__contains__(str(key).lower())

    def get(self, key, default=None):
        return super().get(str(key).lower(), default)

def parse_http_request(raw_bytes):
    if not raw_bytes:
        return None

    header_end = raw_bytes.find(b"\r\n\r\n")
    delimiter_len = 4
    if header_end == -1:
        header_end = raw_bytes.find(b"\n\n")
        delimiter_len = 2

    if header_end != -1:
        header_part = raw_bytes[:header_end].decode("latin-1")
        body_bytes = raw_bytes[header_end + delimiter_len:]
    else:
        header_part = raw_bytes.decode("latin-1")
        body_bytes = b""

    lines = header_part.splitlines()
    if not lines:
        return None

    request_line = lines[0].strip()
    request_parts = request_line.split(" ", 2)
    if len(request_parts) < 2:
        return None

    method = request_parts[0].upper()
    raw_url = request_parts[1]
    http_version = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"

    headers = CaseInsensitiveDict()
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

    host = ""
    port = 80
    path = "/"
    query_string = ""
    query_params = {}

    if method == "CONNECT":
        if ":" in raw_url:
            host_part, port_str = raw_url.split(":", 1)
            host = host_part.strip()
            try:
                port = int(port_str.strip())
            except ValueError:
                port = 443
        else:
            host = raw_url.strip()
            port = 443
    else:
        if raw_url.startswith("http://") or raw_url.startswith("https://"):
            parsed = urllib.parse.urlsplit(raw_url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            query_string = parsed.query
        else:
            header_host = headers.get("host", "")
            if header_host:
                if ":" in header_host:
                    h_parts = header_host.split(":", 1)
                    host = h_parts[0].strip()
                    try:
                        port = int(h_parts[1].strip())
                    except ValueError:
                        port = 80
                else:
                    host = header_host.strip()
                    port = 80

            if "?" in raw_url:
                path_part, query_part = raw_url.split("?", 1)
                path = path_part
                query_string = query_part
            else:
                path = raw_url
                query_string = ""

        if query_string:
            decoded_qs = urllib.parse.unquote_plus(query_string)
            query_params = urllib.parse.parse_qs(decoded_qs, keep_blank_values=True)
            for k, vals in list(query_params.items()):
                query_params[k] = [urllib.parse.unquote_plus(v) for v in vals]

    try:
        body_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        body_text = body_bytes.decode("latin-1", errors="ignore")

    return {
        "method": method,
        "raw_url": raw_url,
        "http_version": http_version,
        "host": host,
        "port": port,
        "path": path,
        "query_string": query_string,
        "query_params": query_params,
        "headers": headers,
        "body": body_text,
        "raw_bytes": raw_bytes
    }


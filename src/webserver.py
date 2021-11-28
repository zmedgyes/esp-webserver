from access_point import AccessPoint
try:
    from typing import TypedDict, List, Dict, Callable
    HTTPRequest = TypedDict("HTTPRequest", {
                            "method": str, "route": str, "protocol_version": str, "headers": List[str], "body": bytearray})
    HTTPResponse = TypedDict("HTTPResponse", {
        "code": int, "status": str, "headers": List[str], "body": bytearray})
    RequestHandler = Callable[[HTTPRequest, HTTPResponse], None]
    MiddlewareHandler = Callable[[HTTPRequest, HTTPResponse], bool]
except ImportError:
    pass

HTTP_STATUS_MESSGAES = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}


def build_http_response(code: int = 200, headers: List[str] = [], body: bytearray = bytearray()) -> HTTPRequest:
    status = "Unknown" if code not in HTTP_STATUS_MESSGAES else HTTP_STATUS_MESSGAES[code]
    return {
        "code": code,
        "status": status,
        "headers": headers,
        "body": body
    }


class WebServer:
    def __init__(self, ap: AccessPoint, debug: bool = False) -> None:
        self._ap = ap
        self._debug = debug
        self.isListening = False
        self._handlers: Dict[str, Dict[str, RequestHandler]] = {}
        self._middlewares: List[MiddlewareHandler] = []

    def listen(self, port: int) -> None:
        self.close()
        self._ap.start_listen(port)
        if self._debug:
            print("WEBSERVER -> Listening on port: ", port)
        self.isListening = True

    def close(self) -> None:
        if self.isListening:
            self._ap.stop_listen()
            if self._debug:
                print("WEBSERVER -> Closed")
            self.isListening = False

    def _parse_query_string(self, query_string: str) -> Dict[str, str]:
        ret = {}
        query_parts = query_string.split("&")
        for key_value in query_parts:
            [key, value] = key_value.split("=")
            ret[key] = value
        return ret

    def register_handler(self, method: str, route: str, handler: RequestHandler) -> None:
        if method not in self._handlers:
            self._handlers[method] = {}
        self._handlers[method][route] = handler

    def deregister_handler(self, method: str, route: str) -> None:
        if method in self._handlers:
            del self._handlers[method][route]

    def register_static_handler(self, route: str, file_root_dir: str) -> None:

        def handler(req, res):
            relative_path = "index.html" if req["route"] == route else req["route"][len(
                route):]
            separator = "" if relative_path.startswith("/") else "/"
            file_path = file_root_dir + separator + relative_path
            if relative_path.find("..") >= 0:
                res.update(build_http_response(
                    403, ["Content-Type: text/html"], b"Invalid file path!"))
            else:
                try:

                    f = open(file_path, "rb")
                    res.update(build_http_response(
                        200, ["Content-Type: text/html"], f.read()))
                    f.close()
                except:
                    res.update(build_http_response(
                        404, ["Content-Type: text/html"], b"File not found!"))

        self.register_handler(
            "GET", route+"**" if route.endswith("/") else route+"/**", handler)

    def deregister_static_handler(self, route: str) -> None:
        self.deregister_handler(
            "GET", route+"**" if route.endswith("/") else route+"/**")

    def _get_handler(self, req: HTTPRequest) -> RequestHandler:
        handlers_by_method = self._handlers[req["method"]]
        if handlers_by_method:
            req_route = req["route"]

            query_separator_pos = req_route.find("?")
            if query_separator_pos > -1:
                req["query"] = self._parse_query_string(
                    req_route[query_separator_pos+1:])
                req_route = req_route[:query_separator_pos]
            else:
                req["query"] = {}

            req_route_parts = req_route.split("/")
            for handler_route in handlers_by_method:
                if self._debug:
                    print("WEBSERVER -> Checking route: ", handler_route)
                handler_route_parts = handler_route.split("/")
                if len(req_route_parts) >= len(handler_route_parts):
                    found = True
                    params = {}
                    for i in range(0, len(handler_route_parts)):
                        if handler_route_parts[i] == "**":
                            break
                        elif handler_route_parts[i] == "*":
                            pass
                        elif handler_route_parts[i].startswith(":"):
                            params[handler_route_parts[i]
                                   [1:]] = req_route_parts[i]
                        elif handler_route_parts[i] != req_route_parts[i]:
                            found = False
                            break
                    if found:
                        req["params"] = params
                        if self._debug:
                            print("WEBSERVER -> Route handler found: ",
                                  handler_route)
                        return handlers_by_method[handler_route]

    def register_middleware(self, middleware: MiddlewareHandler) -> None:
        self._middlewares.append(middleware)

    def deregister_middleware(self, middleware: MiddlewareHandler) -> None:
        self._middlewares.remove(middleware)

    def _apply_middlewares(self, req: HTTPRequest, res: HTTPResponse) -> bool:
        allow_through = True
        for middleware in self._middlewares:
            if not middleware(req, res):
                allow_through = False
                break
        return allow_through

    def _parse_http_request(self, data: bytearray) -> HTTPRequest:
        lines = bytes(data).split(b"\r\n")
        headers = []
        headers_set = False
        body_lines = []
        method = None
        route = None
        protocol_version = None
        for line in lines:
            if method == None:
                (method, route, protocol_version) = str(
                    line, "utf-8").split(" ")
            elif headers_set:
                body_lines.append(line)
            elif line == "":
                headers_set = True
            else:
                headers.append(str(line, "utf-8"))

        return {
            "method": method,
            "route": route,
            "protocol_version": protocol_version,
            "headers": headers,
            "body": b"\r\n".join(body_lines)
        }

    def _build_http_response(self, req: HTTPRequest, res: HTTPResponse) -> bytearray:
        response_lines = []
        status_line_str = req["protocol_version"]
        status_line_str += " %d" % res["code"]
        status_line_str += " "+res["status"]
        response_lines.append(status_line_str.encode())
        for header_line in res["headers"]:
            response_lines.append(header_line.encode())
        response_lines.append(b"")
        response_lines.append(bytes(res["body"]))
        return b"\r\n".join(response_lines)

    def do_receive_cycle(self, timeout: int = 5) -> None:
        if self._debug:
            print("WEBSERVER -> Waiting for request...")
        (link_id, data) = self._ap.socket_receive(timeout)
        if link_id >= 0:
            req = self._parse_http_request(data)
            res = build_http_response()

            handler = self._get_handler(req)
            if handler:
                if self._apply_middlewares(req, res):
                    if self._debug:
                        print("WEBSERVER -> Request:", req)
                    handler(req, res)
            else:
                error_message = "Cannot "+req["method"]+" "+req["route"]
                res = build_http_response(
                    code=404, body=error_message.encode())
            if self._debug:
                print("WEBSERVER -> Response:", res)
            self._ap.socket_send(link_id, self._build_http_response(req, res))
            self._ap.socket_disconnect(link_id)

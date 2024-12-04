class SimpleHTTPProxy(SimpleHTTPRequestHandler):
    proxy_routes = {}

    @classmethod
    def set_routes(cls,proxy_routes):
        cls.proxy_routes = proxy_routes


    def do_GET(self):

        parts = self.path.split('/')
        print(parts)
        live_data = ExtractFeature(parts[3])
        result = predict_model(kmeans,data = live_data)
        print(result['Cluster'][0])
        if result['Cluster'][0] == "Cluster 1":
            print('intrusion Detection')
        if len(parts) >=2:
            self.porxy_request('http://'+parts[2]+'/')
        else:
            super().do_GET()

    def porxy_request(self, url):
        try:
            response = request.urlopen(url)
        except error.HTTPError as e:
            print('err')
            self.send_response_only(e.code)
            self.end_headers()
            return
        self.send_response_only(response.status)
        for name,value in response.headers.items():
            self.send_header(name,value)
        self.end_headers()
        self.copyfile(response, self.wfile)
SimpleHTTPProxy.set_routes({'proxy_route': 'http://demo.testfire.net/'})
with HTTPServer(('127.0.0.1',8080), SimpleHTTPProxy) as httpd:
    host, port = httpd.socket.getsockname()
    print(f'listening on http://{host}:{port}')
    try:
        httpd.serve_forever()
    except keyboardInterrupt:
        print("\nKeyboard interrupt received, exiting.")
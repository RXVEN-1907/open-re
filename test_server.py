#!/usr/bin/env python3
"""Simple HTTP test server for openre-scan integration tests"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Server', 'TestServer/1.0')
            self.send_header('X-Powered-By', 'TestFramework')
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'")
            self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
            self.send_header('Permissions-Policy', 'geolocation=()')
            self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
            self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
            self.end_headers()
            self.wfile.write(b'<html><body><form method="GET"><input type="password" name="pass"></form></body></html>')
        elif self.path == '/robots.txt':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'User-agent: *\nDisallow: /private/')
        elif self.path == '/sitemap.xml':
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.end_headers()
            self.wfile.write(b'<?xml version="1.0"?><urlset></urlset>')
        elif self.path == '/.git/config':
            self.send_response(404)
            self.end_headers()
        elif self.path == '/.env':
            self.send_response(404)
            self.end_headers()
        elif self.path == '/admin':
            self.send_response(403)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/login':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'token': 'test'}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), TestHandler)
    print("Test server running on http://localhost:8080")
    server.serve_forever()
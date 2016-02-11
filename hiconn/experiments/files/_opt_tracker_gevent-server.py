from gevent import monkey
monkey.patch_all()

from wsgiref.simple_server import make_server
import boto3

firehose = boto3.client(
    'firehose',
    region_name='us-east-1',
    aws_access_key_id='FIREHOSE_AWS_KEY',
    aws_secret_access_key='FIREHOSE_AWS_SECRET')


def application(environ, start_response):
    if environ.get('REQUEST_METHOD', '').lower() != 'post':
        start_response('405 Method Not Allowed', [('Content-Type', 'text/plain')])
        yield '405 Method Not Allowed'
    else:
        try:
            body_size = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            body_size = 0
        try:
            body = environ['wsgi.input'].read(body_size)
            # records = [{"Data": line + "\n"} for line in body.splitlines()]
            # firehose.put_record_batch(DeliveryStreamName="firehose-track-1", Records=records)
            record = {"Data": body + "\n"}
            firehose.put_record(DeliveryStreamName="firehose-track-1", Record=record)
            start_response('200 OK', [('Content-Type', 'text/plain')])
            yield ''
        except KeyError:
            start_response('404 Not Found', [('Content-Type', 'text/plain')])
            yield '404 Not Found'
        except:
            start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
            yield '500 Internal Server Error'

if __name__ == "__main__":
    httpd = make_server('', 8001, application)
    httpd.serve_forever()
    httpd.handle_request()

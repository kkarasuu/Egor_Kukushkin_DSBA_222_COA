import grpc
from concurrent import futures
from generated import post_pb2_grpc


class PostService(post_pb2_grpc.PostServiceServicer):
    pass


server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
post_pb2_grpc.add_PostServiceServicer_to_server(PostService(), server)
server.add_insecure_port('[::]:50051')
server.start()
server.wait_for_termination()

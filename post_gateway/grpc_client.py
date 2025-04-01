import grpc
import post_pb2
import post_pb2_grpc

channel = grpc.insecure_channel("post_service:50051")
stub = post_pb2_grpc.PostServiceStub(channel)

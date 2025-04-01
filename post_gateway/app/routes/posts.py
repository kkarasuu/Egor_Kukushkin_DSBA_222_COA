from fastapi import APIRouter, Depends, HTTPException, status
from grpc_client import stub
from schemas import PostCreate, PostUpdate
from utils import get_current_user_id  # уже реализовано для user_service
import post_pb2

router = APIRouter(prefix="/posts", tags=["Posts"])

@router.post("/", status_code=201)
def create_post(post: PostCreate, user_id: int = Depends(get_current_user_id)):
    try:
        grpc_post = post_pb2.CreatePostRequest(
            title=post.title,
            description=post.description,
            creator_id=user_id,
            is_private=post.is_private,
            tags=post.tags
        )
        response = stub.CreatePost(grpc_post)
        return {"post_id": response.id}
    except grpc.RpcError as e:
        raise HTTPException(status_code=500, detail=e.details())

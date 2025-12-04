import ApiError from "../utils/ApiError.js";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import asyncHandler from "../utils/asyncHandler.js";
import { connection as redis } from "../config/redis.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
    const authHeader = req.header("Authorization") || req.header("authorization");

    const token = authHeader?.startsWith("Bearer ")
        ? authHeader.replace("Bearer ", "")
        : authHeader;

    if (!token) {
        throw new ApiError(401, "Unauthorized - No token provided")
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Check Redis cache first
    const cachedUser = await redis.get(`user:${decodedToken?._id}`);
    if (cachedUser) {
        req.user = JSON.parse(cachedUser);

        // Check if account is deactivated (even if cached, though cache should be invalidated on update)
        if (!req.user.isActive) {
            throw new ApiError(401, "Account is deactivated");
        }

        return next();
    }

    const user = await User.findById(decodedToken?._id).select("-password -refreshToken");

    if (!user) {
        throw new ApiError(401, "Invalid access token - User not found")
    }

    if (!user.isActive) {
        throw new ApiError(401, "Account is deactivated");
    }

    // Cache user
    await redis.set(`user:${user._id}`, JSON.stringify(user), 'EX', 3600); // 1 hour

    req.user = user;
    next();
})
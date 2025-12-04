import IORedis from "ioredis";
import ApiError from "../utils/ApiError.js";

const redisUrl = process.env.REDIS_URL;

if (!redisUrl) {
    throw new ApiError(500, "REDIS_URL is missing or invalid in .env file");
}

const connection = new IORedis(redisUrl);

connection.on("ready", () => {
    console.log("Upstash redis connection: ready and connected")
})


connection.on("error", (err) => {
    if (err.message.includes("Authentication failed") ||
        err.message.includes("ECONNREFUSED") ||
        err.message.includes("ENOTFOUND")) {
        throw new ApiError(500, "Cannot connect to Redis", err);
    }
})


export { connection };

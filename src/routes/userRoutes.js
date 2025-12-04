import express from "express";
import {
    createUser,
    loginUser,
    logoutUser,
    getAllUsers,
    getUserById,
    updateUser,
    softDeleteUser,
    hardDeleteUser,
    refreshAccessToken
} from "../controllers/userController.js";
import { verifyJWT } from "../middlewares/Authentication.js";
import { isAdmin, isAdminOrManagerOrSelf } from "../middlewares/Authorization.js";

const router = express.Router();

router.route("/register").post(createUser);
router.route("/login").post(loginUser);
router.route("/refresh-token").post(refreshAccessToken);

router.route("/logout").post(verifyJWT, logoutUser);
router.route("/allUsers").get(verifyJWT, getAllUsers);
router.route("/get-user/:_id").get(verifyJWT, getUserById);
router.route("/update-user/:_id").put(verifyJWT, updateUser);
router.route("/delete-user/:_id").delete(verifyJWT, isAdminOrManagerOrSelf, softDeleteUser);
router.route("/purge-user/:_id").delete(verifyJWT, isAdmin, hardDeleteUser);

export default router;
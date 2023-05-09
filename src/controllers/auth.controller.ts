import { Request, Response } from 'express';
import User from '../models/user.model';
import bcrypt from 'bcrypt';
import { generateAccessToken, generateRefreshToken } from '../utils/generateToken';
import redisClient from '../db/redis';
const authorController = {
    register: async (req: Request, res: Response) => {
        const { email }: { email: string } = req.body;
        if (!email || !req.body.password) {
            return res.status(400).json({
                message: 'Email, password is required',
            });
        }
        try {
            const findUser = await User.findOne({ email: email });
            if (findUser) {
                return res.status(400).json({
                    message: 'Email already exists',
                });
            }
            const salt: string = await bcrypt.genSalt(10);
            const hashPassword: string = await bcrypt.hash(req.body.password, salt);
            const newUser = new User({
                email,
                password: hashPassword,
            });
            const savedUser = await newUser.save();
            const { password, ...info } = savedUser['_doc'];
            return res.status(201).json(info);
        } catch (error) {
            if (error instanceof Error) {
                return res.status(500).json({
                    message: error.message,
                });
            }
        }
    },
    login: async (req: Request, res: Response) => {
        const { email }: { email: string } = req.body;
        if (!email || !req.body.password) {
            return res.status(400).json({
                message: 'Email, password is required',
            });
        }
        try {
            const findUser = await User.findOne({ email: email });
            if (!findUser) {
                return res.status(404).json({
                    message: 'User not found',
                });
            }
            const { password, ...info } = findUser['_doc'];
            const accessToken = generateAccessToken(info);
            const refreshToken = generateRefreshToken(info);
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: false,
                sameSite: 'strict',
                path: '/',
                expires: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
            });
            await redisClient.set(info._id.toString(), refreshToken, {
                EX: 5 * 24 * 60 * 60,
            });
            return res.status(200).json({
                ...info,
                accessToken,
            });
        } catch (error) {
            if (error instanceof Error) {
                return res.status(500).json({
                    message: error.message,
                });
            }
        }
    },
    requestRefreshToken: async function (req: Request, res: Response) {
        try {
            if (req.cookies.refreshToken) {
                //Verify the refresh token
                return res.status(200).json({
                    message: 'Refresh token',
                });
            } else {
                return res.status(401).json({
                    message: 'You not logged in',
                });
            }
        } catch (error) {
            if (error instanceof Error) {
                return res.status(500).json({
                    message: error.message,
                });
            }
        }
    },
    logout: async (req: Request, res: Response) => {
        try {
            // const { userId } = req?.user;
        } catch (error) {
            if (error instanceof Error) {
                return res.status(500).json({
                    message: error.message,
                });
            }
        }
    },
};

export default authorController;

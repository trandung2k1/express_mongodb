import { Request, Response } from 'express';
import User from '../models/user.model';
import bcrypt from 'bcrypt';
import { generateAccessToken, generateRefreshToken } from '../utils/generateToken';
import redisClient from '../db/redis';
import { IPayload, RequestCustom } from '../middlewares/auth.middleware';
import jwt from 'jsonwebtoken';
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
    requestRefreshToken: async function (req: RequestCustom, res: Response) {
        try {
            if (req.cookies.refreshToken) {
                jwt.verify(
                    req.cookies.refreshToken,
                    process.env.REFRESH_TOKEN_SECRET!,
                    async (
                        error: jwt.VerifyErrors | null,
                        decoded: string | jwt.JwtPayload | undefined,
                    ) => {
                        if (error) {
                            if (error.name === 'TokenExpiredError')
                                return res.status(401).json({
                                    message: 'Token expired',
                                });
                            else if (error.name === 'JsonWebTokenError') {
                                return res.status(400).json({
                                    message: error.message,
                                });
                            } else {
                                return res.status(400).json({
                                    message: error?.message,
                                });
                            }
                        } else {
                            const data = decoded as IPayload;
                            if (data && data.userId) {
                                const refreshTokenStore = await redisClient.get(data?.userId);
                                if (req.cookies.refreshToken == null) {
                                    return res.status(401).json({
                                        message: 'Token is not in store',
                                    });
                                }
                                if (req.cookies.refreshToken != refreshTokenStore) {
                                    return res.status(401).json({
                                        message: 'Token is not same in store.',
                                    });
                                }
                                const accessToken = generateAccessToken(data);
                                const refreshToken = generateRefreshToken(data);
                                res.cookie('refreshToken', refreshToken, {
                                    httpOnly: true,
                                    secure: false,
                                    sameSite: 'strict',
                                    path: '/',
                                    expires: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
                                });
                                await redisClient.set(data.userId, refreshToken, {
                                    EX: 5 * 24 * 60 * 60,
                                });
                                return res.status(200).json({
                                    accessToken,
                                });
                            }
                            return res.status(400).json({
                                message: 'Data decoded not found',
                            });
                        }
                    },
                );
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
    logout: async (req: RequestCustom, res: Response) => {
        try {
            const userId = req.userId;
            if (userId && req.accessToken) {
                await redisClient.del(userId?.toString());
                await redisClient.set('BL_' + userId?.toString(), req?.accessToken);
                res.clearCookie('refreshToken');
            }
            return res.status(200).json({
                message: 'Logout',
            });
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

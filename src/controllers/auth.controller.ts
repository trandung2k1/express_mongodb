import { Request, Response } from 'express';
import User from '../models/user.model';
import bcrypt from 'bcrypt';
import { generateAccessToken, generateRefreshToken } from '../utils/generateToken';
import redisClient from '../db/redis';
import { IPayload, RequestCustom } from '../middlewares/auth.middleware';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import transport from '../services/sendMail';
import SMTPTransport from 'nodemailer/lib/smtp-transport';
dotenv.config();
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
            const isValidPassword = await bcrypt.compare(req.body.password, findUser.password);
            if (!isValidPassword) {
                return res.status(400).json({
                    message: 'Wrong password',
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
    forgotPassword: async (req: RequestCustom, res: Response) => {
        const { email } = req.body;
        try {
            const findUser = await User.findOne({ email });
            if (!findUser) {
                return res.status(404).json({
                    message: 'User not found',
                });
            }
            const { password, ...info } = findUser['_doc'];
            const accessToken = jwt.sign(
                {
                    id: info._id,
                    email: info.email,
                },
                process.env.ACCESS_TOKEN_SECRET!,
                {
                    expiresIn: '15m',
                },
            );
            const link = `http://localhost:4000/api/auth/reset-password/${info._id}/${accessToken}`;
            const mailOptions = {
                from: process.env.AUTH_EMAIL,
                to: email,
                subject: 'Reset Password',
                html: `<p>Request a password change for your account.</p><p>This is link <b>exprise in 15 minutes</b>.</p><p>Click the <a href=${link}>here</a> to go to the password change page.</p>`,
            };
            transport.sendMail(
                mailOptions,
                (error: Error | null, info: SMTPTransport.SentMessageInfo) => {
                    if (error) {
                        return res.status(400).json({ message: 'Send mail error' });
                    } else {
                        console.log(info.response);
                        return res.status(200).json({
                            message: 'Send mail successfully. Please check your mailbox!',
                        });
                    }
                },
            );
        } catch (error) {
            if (error instanceof Error) {
                return res.status(500).json({
                    message: error.message,
                });
            }
        }
    },
    resetPassword: async (req: Request, res: Response) => {
        const { id, token } = req.params;
        try {
            const findUser = await User.findById(id);
            if (!findUser) {
                return res.status(404).json({
                    message: 'User not found',
                });
            }
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, async (error, decoded) => {
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
                }
                const data = decoded as jwt.JwtPayload & { id?: string; email: string };
                return res.render('index', {
                    title: 'HomePage',
                    email: data.email,
                    status: 'not verified',
                });
            });
        } catch (error) {
            if (error instanceof Error) {
                return res.status(500).json({
                    message: error.message,
                });
            }
        }
    },
    confirmResetPassword: async (req: Request, res: Response) => {
        const { id, token } = req.params;
        const { password } = req.body;
        try {
            const findUser = await User.findById(id);
            if (!findUser) {
                return res.status(404).json({
                    message: 'User not found',
                });
            }
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, async (error, decoded) => {
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
                }
                const salt = await bcrypt.genSalt(10);
                const hashPassword = await bcrypt.hash(password, salt);
                await User.findByIdAndUpdate(
                    id,
                    {
                        password: hashPassword,
                    },
                    {
                        new: true,
                    },
                );
                const data = decoded as jwt.JwtPayload & { id?: string; email: string };
                return res.render('index', {
                    title: 'HomePage',
                    email: data.email,
                    status: 'verified',
                });
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

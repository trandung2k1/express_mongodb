import jwt from 'jsonwebtoken';
import { IUserToken } from '../types/user';
import dotenv from 'dotenv';
dotenv.config();
export const generateAccessToken = (user: IUserToken) => {
    return jwt.sign(
        { userId: user._id ? user._id : user.userId },
        process.env?.ACCESS_TOKEN_SECRET!,
        {
            expiresIn: '15m',
        },
    );
};
export const generateRefreshToken = (user: IUserToken) => {
    return jwt.sign(
        { userId: user._id ? user._id : user.userId },
        process.env?.REFRESH_TOKEN_SECRET!,
        {
            expiresIn: '5d',
        },
    );
};

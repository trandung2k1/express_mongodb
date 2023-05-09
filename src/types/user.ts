import mongoose from 'mongoose';

export interface IUser {
    email: string;
    password: string;
}
export interface IUserToken {
    _id?: string;
    userId?: string;
}

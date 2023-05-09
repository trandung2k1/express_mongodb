import mongoose from 'mongoose';

export interface IUser {
    email: string;
    password: string;
}
export interface IUserToken {
    _id: mongoose.Types.ObjectId;
    email: string;
    createdAt: Date;
    updatedAt: Date;
    __v: number;
}

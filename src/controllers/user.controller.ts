import e, { Response, Request } from 'express';
import User from '../models/user.model';
const userController = {
    getAllUser: async (req: Request, res: Response) => {
        try {
            const users = await User.find({});
            const filterFieldUsers = users.map((user) => {
                delete user.password;
                return user;
            });
            return res.status(200).json(filterFieldUsers);
        } catch (error) {
            if (error instanceof Error) {
                return res.status(500).json({
                    message: error.message,
                });
            }
        }
    },
};

export default userController;

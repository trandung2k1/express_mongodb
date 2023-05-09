import { Express } from 'express';
import auth from './auth.route';
import user from './user.route';
const routes = (app: Express) => {
    app.use('/api/auth', auth);
    app.use("/api/users", user)
};

export default routes;

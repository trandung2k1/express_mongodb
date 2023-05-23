import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
dotenv.config();
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import colors from 'colors';
import cors from 'cors';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import corsOptions from './middlewares/cors.middleware';
import { errorHandler, notFound } from './middlewares/handlerError.middleware';
import connectDB from './db/mongodb';
import routes from './routes';
import transport from './services/sendMail';
import viewEngine from './config/viewEngine';
const port: number = parseInt(process.env.PORT!) || 4000;
const app: Express = express();
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '10mb' }));
app.use(cors(corsOptions));
app.use(helmet());
app.use(cookieParser());
app.use(morgan('combined'));
transport.verify((error: Error | null, success: boolean) => {
    if (error) {
        console.log(colors.red(error.message));
    } else {
        console.log(colors.green('Ready for message'));
        console.log(success);
    }
});
viewEngine(app);
app.get('/', (req: Request, res: Response) => {
    return res.status(200).json({
        message: 'Welcome to the server 👋👋',
    });
});
routes(app);
app.use(notFound);
app.use(errorHandler);
app.listen(port, async (): Promise<void> => {
    await connectDB();
    console.log(colors.green(`Server listening on http://localhost:${port}`));
}).on('error', (e: Error) => {
    console.log(e);
    process.exit(1);
});

import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';
dotenv.config();

const sequelize = new Sequelize(
	process.env.DB_NAME,
	process.env.DB_USERNAME,
	process.env.DB_PASSWORD,
	{
		host: process.env.DB_HOST,
		dialect: 'mysql',
		dialectOptions: {
			ssl: {
				required: false
			}
		}
	}
);

const connect = async () => {
	try {
		await sequelize.authenticate();
		console.log('Banco conectado com sucesso.');
	} catch (error) {
		console.log(error);
	}
};

connect()

export default sequelize
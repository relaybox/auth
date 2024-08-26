import nodemailer from 'nodemailer';

const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_USERNAME = process.env.SMTP_USERNAME || '';
const SMTP_PASSWORD = process.env.SMTP_PASSWORD || '';

export const smtpTransport = nodemailer.createTransport({
  host: SMTP_HOST,
  port: 2465,
  secure: true,
  auth: {
    user: SMTP_USERNAME,
    pass: SMTP_PASSWORD
  }
});

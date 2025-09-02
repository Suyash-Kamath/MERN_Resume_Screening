const express = require('express');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, GridFSBucket, ObjectId } = require('mongodb');
const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// PDF processing
const pdf = require('pdf-parse');
const mammoth = require('mammoth');
const cheerio = require('cheerio');

// OpenAI
const OpenAI = require('openai');

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "https://final-resume-screening-app.vercel.app",
    "https://prohire.probusinsurance.com"
  ],
  credentials: true,
  methods: ["*"],
  allowedHeaders: ["*"]
}));

// MongoDB setup
let db, misCollection, recruitersCollection, resetTokensCollection, gfs;
const MONGODB_URI = process.env.MONGODB_URI;

async function connectToDatabase() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log('Connected to MongoDB');
    
    db = client.db('resume_screening');
    misCollection = db.collection('mis');
    recruitersCollection = db.collection('recruiters');
    resetTokensCollection = db.collection('reset_tokens');
    gfs = new GridFSBucket(db);
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
}

// JWT and Auth configuration
const SECRET_KEY = process.env.SECRET_KEY || "supersecretkey";
const ALGORITHM = "HS256";
const ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7; // 1 week
const RESET_TOKEN_EXPIRE_MINUTES = 30; // 30 minutes

// Email configuration
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_SERVER,
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Helper functions
const hashPassword = async (password) => {
  return await bcrypt.hash(password, 12);
};

const verifyPassword = async (plainPassword, hashedPassword) => {
  return await bcrypt.compare(plainPassword, hashedPassword);
};

const createAccessToken = (data, expiresIn = '7d') => {
  return jwt.sign(data, SECRET_KEY, { expiresIn, algorithm: ALGORITHM });
};

const createResetToken = (email) => {
  const expire = new Date(Date.now() + RESET_TOKEN_EXPIRE_MINUTES * 60 * 1000);
  return jwt.sign({ email, exp: Math.floor(expire.getTime() / 1000), type: 'reset' }, SECRET_KEY, { algorithm: ALGORITHM });
};

const verifyResetToken = (token) => {
  try {
    const payload = jwt.verify(token, SECRET_KEY, { algorithms: [ALGORITHM] });
    if (payload.type !== 'reset') return null;
    return payload.email;
  } catch (error) {
    return null;
  }
};

const sendEmail = async (toEmail, subject, body, isHtml = false) => {
  try {
    const mailOptions = {
      from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`,
      to: toEmail,
      subject: subject,
      [isHtml ? 'html' : 'text']: body
    };

    await emailTransporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Failed to send email:', error);
    return false;
  }
};

const formatDateWithDay = (date) => {
  const day = date.getDate();
  const suffix = (day >= 10 && day <= 20) ? 'th' : 
                 (day % 10 === 1) ? 'st' : 
                 (day % 10 === 2) ? 'nd' : 
                 (day % 10 === 3) ? 'rd' : 'th';
  
  const options = { 
    year: 'numeric', 
    month: 'long', 
    weekday: 'long' 
  };
  
  const formatted = date.toLocaleDateString('en-US', options);
  return `${day}${suffix} ${formatted.split(' ').slice(1).join(' ')}`;
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ detail: 'Access token required' });
  }

  try {
    const payload = jwt.verify(token, SECRET_KEY, { algorithms: [ALGORITHM] });
    const recruiter = await recruitersCollection.findOne({ username: payload.sub });
    
    if (!recruiter) {
      return res.status(401).json({ detail: 'Invalid credentials' });
    }
    
    req.recruiter = recruiter;
    next();
  } catch (error) {
    return res.status(401).json({ detail: 'Invalid token' });
  }
};
const extractTextFromImageBuffer = async (buffer, originalFormat = "image") => {
  try {
    console.log(`Starting OCR for ${originalFormat}`);

    const base64Image = buffer.toString("base64");

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        {
          role: "user",
          content: [
            {
              type: "text",
              text: "Extract all text from this image/PDF. Return only the raw text, no explanations."
            },
            {
              type: "image_url",
              image_url: { url: `data:image/jpeg;base64,${base64Image}` }
            }
          ]
        }
      ],
      max_tokens: 1000,
      temperature: 0
    });

    const extractedText = response.choices?.[0]?.message?.content?.trim();
    if (extractedText) {
      console.log(`✅ OCR extracted ${extractedText.length} characters`);
      return extractedText;
    }

    return "❌ No text could be extracted from the image.";
  } catch (error) {
    console.error("OCR extraction error:", error);
    return `❌ Error extracting text from image: ${error.message}`;
  }
};

/* ---------------- Scanned PDF → Images → OCR ---------------- */
const { convert } = require("pdf-poppler");
const extractTextFromScannedPdf = async (filePath) => {
  try {
    const outputDir = path.join(__dirname, "tmp");
    fs.mkdirSync(outputDir, { recursive: true });

    const options = {
      format: "jpeg",
      out_dir: outputDir,
      out_prefix: path.basename(filePath, path.extname(filePath)),
      page: null, // null = all pages
    };

    await convert(filePath, options);

    const files = fs.readdirSync(outputDir).filter((f) => f.endsWith(".jpg"));
    let text = "";

    for (const file of files) {
      const buffer = fs.readFileSync(path.join(outputDir, file));
      const pageText = await extractTextFromImageBuffer(buffer, "pdf-page");
      text += "\n" + pageText;
    }

    return text.trim() || "❌ No text extracted from scanned PDF.";
  } catch (err) {
    console.error("❌ Scanned PDF extraction failed:", err);
    return "❌ Could not extract text from scanned PDF.";
  }
};

/* ---------------- PDF Extraction ---------------- */
const extractTextFromPdf = async (buffer, filePath) => {
  try {
    const data = await pdf(buffer);
    if (data.text && data.text.trim()) {
      return data.text.trim();
    }

    if (filePath) {
      console.log("⚠️ PDF has no embedded text → trying OCR via images");
      return await extractTextFromScannedPdf(filePath);
    }

    return "❌ PDF appears scanned. Please provide original or DOCX.";
  } catch (err) {
    console.error("PDF parse error:", err);
    if (filePath) {
      return await extractTextFromScannedPdf(filePath);
    }
    return "❌ Failed to process PDF.";
  }
};

/* ---------------- DOCX Extraction ---------------- */
const extractTextFromDocx = async (buffer) => {
  try {
    const result = await mammoth.extractRawText({ buffer });
    if (result.value && result.value.trim()) {
      return result.value.trim();
    }
    return "❌ Unable to extract text from DOCX file.";
  } catch (error) {
    console.error("DOCX extraction error:", error);
    return `❌ Error extracting text from DOCX: ${error.message}`;
  }
};

/* ---------------- DOC Extraction ---------------- */
const extractTextFromDoc = async (buffer) => {
  try {
    const content = buffer.toString("utf-8");

    if (content.includes("<html") || content.includes("<body") || content.includes("<div")) {
      const $ = cheerio.load(content);
      $("script, style").remove();
      const text = $.text().replace(/\s+/g, " ").trim();
      if (text.length > 10) return text;
    }

    const result = await mammoth.extractRawText({ buffer });
    if (result.value && result.value.trim().length > 10) {
      return result.value.trim();
    }

    return "❌ Unable to extract text from DOC file. Please convert to PDF or DOCX.";
  } catch (error) {
    console.error("DOC extraction error:", error);
    return `❌ Error extracting text from DOC: ${error.message}`;
  }
};

const analyzeResume = async (jd, resumeText, hiringChoice, levelChoice) => {
  let prompt = "";
  
  if (hiringChoice === "1") {
    if (levelChoice === "1") {
      prompt = `
You are a professional HR assistant AI screening resumes for a **Sales Fresher** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: 
   - Candidate must be either from the job location city (e.g., Kolkata) or nearby cities (e.g., Durgapur) within feasible travel distance.
   - If candidate is not in the exact city but lives in a nearby town and the job allows remote or field sales operations, they should be considered.
   - Candidate should be able to travel to the main office once a month for reporting.
2. Age: As per job description.
3. Education: 12th pass & above.
4. Gender: As per job description.

Note: Everything should match the Job Description.

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    } else if (levelChoice === "2") {
      prompt = `
You are a professional HR assistant AI screening resumes for a **Sales Experienced** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: 
   - Candidate must be either from the job location city (e.g., Kolkata) or nearby cities (e.g., Durgapur) within feasible travel distance.
   - If candidate is not in the exact city but lives in a nearby town and the job allows remote or field sales operations, they should be considered.
   - Candidate should be able to travel to the main office once a month for reporting.
2. Age: As per job description ("up to" logic preferred).
3. Total Experience: Add all types of sales (health + motor, etc.).
4. Relevant Experience: Must match industry (strict).
5. Education: 12th pass & above accepted.
6. Gender: As per job description.
7. Skills: Skills should align with relevant experience.
8. Stability: Ignore if 1 job <1 year; Reject if 2+ jobs each <1 year.

Note: Everything should match the Job Description.

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    }
  } else if (hiringChoice === "2") {
    if (levelChoice === "1") {
      prompt = `
You are a professional HR assistant AI screening resumes for an **IT Fresher** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: Must be local.
2. Age: Ignore or as per JD.
3. Experience: Internship is a bonus; no experience is fine.
4. Projects: Highlighted as experience if relevant.
5. Education: B.E, M.E, BTech, MTech, or equivalent in IT.
6. Gender: As per job description.
7. Skills: Must align with the job field (e.g., Full Stack).
Note: For example, if hiring for a Full Stack Engineer role, even if one or two skills mentioned in the Job Description are missing, the candidate can still be considered if they have successfully built Full Stack projects. Additional skills or tools mentioned in the JD are good-to-have, but not mandatory.
8. Stability: Not applicable.

Note: Everything should match the Job Description.

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    } else if (levelChoice === "2") {
      prompt = `
You are a professional HR assistant AI screening resumes for an **IT Experienced** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: Must be local.
2. Age: As per job description (prefer "up to").
3. Total Experience: Overall IT field experience.
4. Relevant Experience: Must align with JD field.
5. Education: IT-related degrees only (B.E, M.Tech, etc.).
6. Gender: As per job description.
7. Skills: Languages and frameworks should match JD.
8. Stability: Ignore if 1 company <1 year; Reject if 2+ companies each <1 year.

Note: Everything should match the Job Description.

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    }
  } else if (hiringChoice === "3") {
    if (levelChoice === "1") {
      prompt = `
You are a professional HR assistant AI screening resumes for a **Non-Sales Fresher** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: Should be local and match JD.
2. Age: As per JD.
3. Total / Relevant Experience: Internship optional, but candidate should have certifications.
4. Education: Must be relevant to the JD.
5. Gender: As per JD.
6. Skills: Must align with the JD.
7. Stability: Not applicable for freshers.

Note: Don't reject or make decisions based on age, gender and location , it was just for an extra information you can include in your evaluation. Take your decision overall based on role , responsibilities and skills

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    } else if (levelChoice === "2") {
      prompt = `
You are a professional HR assistant AI screening resumes for a **Non-Sales Experienced** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: Must strictly match the JD.
2. Age: As per JD.
3. Total Experience: Overall professional experience.
4. Relevant Experience: Must align with role in JD.
5. Education: Must match the JD.
6. Gender: As per JD.
7. Skills: Should align with JD and match relevant experience (skills = relevant experience).
8. Stability:
   - If 2+ companies and each job ≤1 year → Reject.
   - If 1 company and ≤1 year → Ignore stability.

Note: Don't reject or make decisions based on age, gender and location , it was just for an extra information you can include in your evaluation. Take your decision overall based on role , responsibilities and skills

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    }
  } else if (hiringChoice === "4") {
    if (levelChoice === "1") {
      prompt = `
You are a professional HR assistant AI screening resumes for a **Sales Support Fresher** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: Must be strictly local.
2. Age: As per job description.
3. Education: 12th pass & above.
4. Gender: As per job description.

Note: Everything should match the Job Description.

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    } else if (levelChoice === "2") {
      prompt = `
You are a professional HR assistant AI screening resumes for a **Sales Support Experienced** role.

--- Job Description ---
${jd}

--- Candidate Resume ---
${resumeText}

--- Screening Criteria ---
1. Location: Must be strictly local.
2. Age: As per job description ("up to" logic preferred).
3. Total Experience: Add all types of sales support
4. Relevant Experience: Must match industry (strict).
5. Education: 12th pass & above accepted.
6. Gender: As per job description.
7. Skills: Skills should align with relevant experience.
8. Stability: Ignore if 1 job <1 year; Reject if 2+ jobs each <1 year.

Note: Everything should match the Job Description.

--- Response Format ---
Match %: XX%
Pros:
- ...
Cons:
- ...
Decision: ✅ Shortlist or ❌ Reject
Reason (if Rejected): ...
`;
    }
  }

  if (!prompt) {
    return "❌ Error: Invalid hiring or level choice provided.";
  }

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
      max_tokens: 800
    });

    const content = response.choices[0].message.content;
    let resultText = content ? content.trim() : "Match %: 0\nDecision: ❌ Reject\nReason (if Rejected): No response from model.";
    
    // Extract match percentage
    let matchPercent = 0;
    const matchLine = resultText.match(/Match\s*%:\s*(\d+)/);
    if (matchLine) {
      matchPercent = parseInt(matchLine[1]);
    }

    if (matchPercent < 72) {
      resultText = resultText.replace(/Decision:.*$/, "Decision: ❌ Reject");
      if (resultText.includes("Reason (if Rejected):")) {
        resultText = resultText.replace(/Reason \(if Rejected\):.*$/, "Reason (if Rejected): Match % below 72% threshold.");
      } else {
        resultText += "\nReason (if Rejected): Match % below 72% threshold.";
      }
    }

    return {
      result_text: resultText,
      match_percent: matchPercent,
      usage: response.usage
    };
  } catch (error) {
    console.error('Analyze resume error:', error);
    return "❌ Error analyzing resume.";
  }
};

const getHiringTypeLabel = (hiringType) => {
  const labels = { "1": "Sales", "2": "IT", "3": "Non-Sales", "4": "Sales Support" };
  return labels[hiringType] || hiringType;
};

const getLevelLabel = (level) => {
  const labels = { "1": "Fresher", "2": "Experienced" };
  return labels[level] || level;
};

// Routes

// Register
app.post(['/register','/backend/register'], async (req, res) => {
  try {
    let { username, password, email } = req.body;
    username = username.trim();
    email = email.trim().toLowerCase();

    const existingUsername = await recruitersCollection.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ detail: "Username already registered" });
    }

    const existingEmail = await recruitersCollection.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ detail: "Email already registered" });
    }

    const hashed = await hashPassword(password);

    await recruitersCollection.insertOne({
      username,
      email,
      hashed_password: hashed,
      created_at: new Date()
    });

    res.json({ msg: "Recruiter registered successfully" });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Legacy register-form
app.post(['/register-form','/backend/register-form'], upload.none(), async (req, res) => {
  try {
    const { username, password } = req.body;
    const trimmedUsername = username.trim();

    const existing = await recruitersCollection.findOne({ username: trimmedUsername });
    if (existing) {
      return res.status(400).json({ detail: "Username already registered" });
    }

    const hashed = await hashPassword(password);

    await recruitersCollection.insertOne({
      username: trimmedUsername,
      hashed_password: hashed,
      created_at: new Date()
    });

    res.json({ msg: "Recruiter registered" });
  } catch (error) {
    console.error('Register form error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Login
app.post(['/login','/backend/login'], upload.none(), async (req, res) => {
  try {
    const { username, password } = req.body;
    const trimmedUsername = username.trim();

    const recruiter = await recruitersCollection.findOne({ username: trimmedUsername });
    if (!recruiter || !(await verifyPassword(password, recruiter.hashed_password))) {
      return res.status(400).json({ detail: "Incorrect username or password" });
    }

    const accessToken = createAccessToken({ sub: recruiter.username });

    res.json({
      access_token: accessToken,
      token_type: "bearer",
      recruiter_name: recruiter.username
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Forgot password
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const trimmedEmail = email.trim().toLowerCase();

    const recruiter = await recruitersCollection.findOne({ email: trimmedEmail });
    if (!recruiter) {
      return res.json({ msg: "If the email exists, you will receive a password reset link" });
    }

    const resetToken = createResetToken(trimmedEmail);

    await resetTokensCollection.insertOne({
      email: trimmedEmail,
      token: resetToken,
      created_at: new Date(),
      expires_at: new Date(Date.now() + RESET_TOKEN_EXPIRE_MINUTES * 60 * 1000),
      used: false
    });

    const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL;
    const resetLink = `${FRONTEND_BASE_URL}/reset-password?token=${resetToken}`;

    const subject = "Password Reset Request - Prohire";
    const body = `
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello ${recruiter.username},</p>
            <p>You have requested to reset your password for Prohire</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="${resetLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">Reset Password</a></p>
            <p>This link will expire in ${RESET_TOKEN_EXPIRE_MINUTES} minutes.</p>
            <p>If you didn't request this reset, please ignore this email.</p>
            <br>
            <p>Best regards,<br>ProHire Team</p>
        </body>
    </html>
    `;

    const emailSent = await sendEmail(trimmedEmail, subject, body, true);
    if (!emailSent) {
      return res.status(500).json({ detail: "Failed to send reset email" });
    }

    res.json({ msg: "If the email exists, you will receive a password reset link" });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Reset password
app.post('/reset-password', async (req, res) => {
  try {
    const { token, new_password } = req.body;

    const email = verifyResetToken(token);
    if (!email) {
      return res.status(400).json({ detail: 'Invalid or expired reset token' });
    }

    const tokenDoc = await resetTokensCollection.findOne({
      token,
      used: false,
      expires_at: { $gt: new Date() }
    });

    if (!tokenDoc) {
      return res.status(400).json({ detail: 'Invalid or expired reset token' });
    }

    const recruiter = await recruitersCollection.findOne({ email });
    if (!recruiter) {
      return res.status(404).json({ detail: 'User not found' });
    }

    const hashedPassword = await hashPassword(new_password);

    await recruitersCollection.updateOne(
      { email },
      {
        $set: {
          hashed_password: hashedPassword,
          password_updated_at: new Date()
        }
      }
    );

    await resetTokensCollection.updateOne(
      { token },
      { $set: { used: true, used_at: new Date() } }
    );

    res.json({ msg: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Verify reset token
app.get('/verify-reset-token/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const email = verifyResetToken(token);
    if (!email) {
      return res.status(400).json({ detail: 'Invalid or expired reset token' });
    }

    const tokenDoc = await resetTokensCollection.findOne({
      token,
      used: false,
      expires_at: { $gt: new Date() }
    });

    if (!tokenDoc) {
      return res.status(400).json({ detail: 'Invalid or expired reset token' });
    }

    res.json({ valid: true, email });
  } catch (error) {
    console.error('Verify reset token error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Cleanup expired tokens
app.delete('/cleanup-expired-tokens', async (req, res) => {
  try {
    const result = await resetTokensCollection.deleteMany({
      expires_at: { $lt: new Date() }
    });

    res.json({ deleted_count: result.deletedCount });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Analyze resumes
app.post(['/analyze-resumes', '/analyze-resumes/', '/backend/analyze-resumes', '/backend/analyze-resumes/'], upload.array('files'), authenticateToken, async (req, res) => {
  try {
    const { job_description, hiring_type, level } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ detail: 'No files provided' });
    }
    
    const results = [];
    let shortlisted = 0;
    let rejected = 0;
    const history = [];
    const currentDate = new Date();
    const hiringTypeLabel = getHiringTypeLabel(hiring_type);
    const levelLabel = getLevelLabel(level);
    
    for (const file of files) {
      const filename = file.originalname || 'Unknown';
      const fileExtension = path.extname(filename).toLowerCase();
      console.log(`Processing file: ${filename} with extension: ${fileExtension}`);
      
      const supportedImages = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'];
      
      // Store file in GridFS
      let fileId = null;
      try {
        const uploadStream = gfs.openUploadStream(filename, {
          metadata: {
            content_type: file.mimetype || 'application/octet-stream',
            upload_date: currentDate,
            recruiter_name: req.recruiter.username,
            file_size: file.size
          }
        });
        
        uploadStream.end(file.buffer);
        fileId = uploadStream.id;
        console.log(`File stored in GridFS with ID: ${fileId}`);
      } catch (error) {
        console.error('Failed to store file in GridFS:', error);
      }
      
      let resumeText;
      
      // Process different file types
      if (fileExtension === '.pdf') {
        resumeText = await extractTextFromPdf(file.buffer);
      } else if (fileExtension === '.docx') {
        resumeText = await extractTextFromDocx(file.buffer);
      } else if (fileExtension === '.doc') {
        resumeText = await extractTextFromDoc(file.buffer);
      } else if (supportedImages.includes(fileExtension)) {
        console.log(`Processing image file: ${filename} with extension: ${fileExtension}`);
        resumeText = await extractTextFromImageBuffer(file.buffer, 'image');
      } else {
        const errorMsg = `Unsupported file type: ${fileExtension}. Only PDF, DOCX, DOC, and image files (JPG, JPEG, PNG, GIF, BMP, TIFF, WEBP) are allowed.`;
        console.log(`File rejected: ${filename} with extension: ${fileExtension}`);
        
        results.push({
          filename: filename,
          error: errorMsg
        });
        
        history.push({
          resume_name: filename,
          hiring_type: hiringTypeLabel,
          level: levelLabel,
          match_percent: null,
          decision: 'Error',
          details: errorMsg,
          upload_date: formatDateWithDay(currentDate),
          file_id: fileId ? fileId.toString() : null
        });
        continue;
      }
      
      // Analyze resume
      const analysis = await analyzeResume(job_description, resumeText, hiring_type, level);
      
      if (typeof analysis === 'object' && analysis.result_text) {
        analysis.filename = filename;
        
        // Extract decision
        let decision = analysis.decision;
        if (!decision && analysis.result_text) {
          const match = analysis.result_text.match(/Decision:\s*(✅ Shortlist|❌ Reject)/);
          if (match) {
            decision = match[1];
          }
        }
        
        if (decision && decision.includes('Shortlist')) {
          shortlisted++;
        } else if (decision && decision.includes('Reject')) {
          rejected++;
        }
        
        const decisionLabel = decision && decision.includes('Shortlist') ? 'Shortlisted' :
                             decision && decision.includes('Reject') ? 'Rejected' : '-';
        
        analysis.decision = decisionLabel;
        results.push(analysis);
        
        history.push({
          resume_name: filename,
          hiring_type: hiringTypeLabel,
          level: levelLabel,
          match_percent: analysis.match_percent,
          decision: decisionLabel,
          details: analysis.result_text || analysis.error || '',
          upload_date: formatDateWithDay(currentDate),
          file_id: fileId ? fileId.toString() : null
        });
      } else {
        results.push({ filename: filename, error: analysis });
        history.push({
          resume_name: filename,
          hiring_type: hiringTypeLabel,
          level: levelLabel,
          match_percent: null,
          decision: 'Error',
          details: analysis,
          upload_date: formatDateWithDay(currentDate),
          file_id: fileId ? fileId.toString() : null
        });
      }
    }
    
    // Save MIS record with history
    await misCollection.insertOne({
      recruiter_name: req.recruiter.username,
      total_resumes: files.length,
      shortlisted: shortlisted,
      rejected: rejected,
      timestamp: currentDate,
      history: history
    });
    
    res.json({ results: results });
  } catch (error) {
    console.error('Analyze resumes error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Download resume
app.get(['/download-resume/:file_id','/backend/download-resume/:file_id'], authenticateToken, async (req, res) => {
  try {
    const { file_id } = req.params;
    
    const downloadStream = gfs.openDownloadStream(new ObjectId(file_id));
    
    downloadStream.on('error', (error) => {
      console.error('Download error:', error);
      res.status(404).json({ detail: 'File not found' });
    });
    
    downloadStream.on('file', (file) => {
      res.set({
        'Content-Type': file.metadata?.content_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${file.filename}"`
      });
    });
    
    downloadStream.pipe(res);
  } catch (error) {
    console.error('Download resume error:', error);
    res.status(404).json({ detail: 'File not found' });
  }
});

// View resume
app.get(['/view-resume/:file_id','/backend/view-resume/:file_id'], authenticateToken, async (req, res) => {
  try {
    const { file_id } = req.params;
    
    const downloadStream = gfs.openDownloadStream(new ObjectId(file_id));
    const chunks = [];
    let fileMeta = null;
    
    downloadStream.on('file', (file) => {
      fileMeta = file;
    });
    
    downloadStream.on('data', (chunk) => {
      chunks.push(chunk);
    });
    
    downloadStream.on('end', () => {
      if (!fileMeta) {
        return res.status(404).json({ detail: 'File not found' });
      }
      const fileContent = Buffer.concat(chunks);
      res.json({
        filename: fileMeta.filename,
        content_type: fileMeta.metadata?.content_type || 'application/octet-stream',
        size: fileContent.length,
        content: fileContent.toString('base64')
      });
    });
    
    downloadStream.on('error', (error) => {
      console.error('View resume error:', error);
      res.status(404).json({ detail: 'File not found' });
    });
  } catch (error) {
    console.error('View resume error:', error);
    res.status(404).json({ detail: 'File not found' });
  }
});

// MIS Summary
app.get(['/mis-summary','/backend/mis-summary'], async (req, res) => {
  try {
    const pipeline = [
      {
        $group: {
          _id: "$recruiter_name",
          uploads: { $sum: 1 },
          total_resumes: { $sum: "$total_resumes" },
          shortlisted: { $sum: "$shortlisted" },
          rejected: { $sum: "$rejected" },
          history: { $push: "$history" }
        }
      },
      { $sort: { _id: 1 } }
    ];
    
    const summary = [];
    const cursor = misCollection.aggregate(pipeline);
    
    for await (const row of cursor) {
      const flatHistory = row.history.flat();
      
      const dailyCounts = {};
      flatHistory.forEach(item => {
        const uploadDate = item.upload_date || '';
        if (uploadDate) {
          const datePart = uploadDate.includes(',') ? uploadDate.split(',')[0] : uploadDate;
          dailyCounts[datePart] = (dailyCounts[datePart] || 0) + 1;
        }
      });
      
      flatHistory.forEach(item => {
        const uploadDate = item.upload_date || '';
        if (uploadDate) {
          const datePart = uploadDate.includes(',') ? uploadDate.split(',')[0] : uploadDate;
          item.counts_per_day = dailyCounts[datePart] || 0;
        } else {
          item.counts_per_day = 0;
        }
      });
      
      summary.push({
        recruiter_name: row._id,
        uploads: row.uploads,
        resumes: row.total_resumes,
        shortlisted: row.shortlisted,
        rejected: row.rejected,
        history: flatHistory
      });
    }
    
    res.json({ summary: summary });
  } catch (error) {
    console.error('MIS summary error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Daily reports
app.get(['/daily-reports','/backend/daily-reports'], async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    const pipeline = [
      {
        $match: {
          timestamp: {
            $gte: today,
            $lt: tomorrow
          }
        }
      },
      {
        $group: {
          _id: "$recruiter_name",
          total_resumes: { $sum: "$total_resumes" },
          shortlisted: { $sum: "$shortlisted" },
          rejected: { $sum: "$rejected" }
        }
      },
      { $sort: { _id: 1 } }
    ];
    
    const dailyData = [];
    const cursor = misCollection.aggregate(pipeline);
    
    for await (const row of cursor) {
      dailyData.push({
        recruiter_name: row._id,
        total_resumes: row.total_resumes,
        shortlisted: row.shortlisted,
        rejected: row.rejected
      });
    }
    
    const todayFormatted = formatDateWithDay(today);
    
    res.json({
      date: todayFormatted,
      reports: dailyData
    });
  } catch (error) {
    console.error('Daily reports error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Previous day reports
app.get(['/previous-day-reports','/backend/previous-day-reports'], async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    const pipeline = [
      {
        $match: {
          timestamp: {
            $gte: yesterday,
            $lt: today
          }
        }
      },
      {
        $group: {
          _id: "$recruiter_name",
          total_resumes: { $sum: "$total_resumes" },
          shortlisted: { $sum: "$shortlisted" },
          rejected: { $sum: "$rejected" }
        }
      },
      { $sort: { _id: 1 } }
    ];
    
    const previousDayData = [];
    const cursor = misCollection.aggregate(pipeline);
    
    for await (const row of cursor) {
      previousDayData.push({
        recruiter_name: row._id,
        total_resumes: row.total_resumes,
        shortlisted: row.shortlisted,
        rejected: row.rejected
      });
    }
    
    const yesterdayFormatted = formatDateWithDay(yesterday);
    
    res.json({
      date: yesterdayFormatted,
      reports: previousDayData
    });
  } catch (error) {
    console.error('Previous day reports error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Reports by date
app.get(['/reports/:date_type','/backend/reports/:date_type'], async (req, res) => {
  try {
    const { date_type } = req.params;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    let startDate, endDate;
    
    if (date_type === 'today') {
      startDate = today;
      endDate = new Date(today);
      endDate.setDate(endDate.getDate() + 1);
    } else if (date_type === 'yesterday') {
      startDate = new Date(today);
      startDate.setDate(startDate.getDate() - 1);
      endDate = today;
    } else {
      try {
        const parsedDate = new Date(date_type + 'T00:00:00.000Z');
        if (isNaN(parsedDate.getTime())) {
          throw new Error('Invalid date');
        }
        startDate = parsedDate;
        endDate = new Date(parsedDate);
        endDate.setDate(endDate.getDate() + 1);
      } catch (error) {
        return res.status(400).json({ 
          detail: "Invalid date format. Use 'today', 'yesterday', or YYYY-MM-DD" 
        });
      }
    }
    
    const pipeline = [
      {
        $match: {
          timestamp: {
            $gte: startDate,
            $lt: endDate
          }
        }
      },
      {
        $group: {
          _id: "$recruiter_name",
          total_resumes: { $sum: "$total_resumes" },
          shortlisted: { $sum: "$shortlisted" },
          rejected: { $sum: "$rejected" }
        }
      },
      { $sort: { _id: 1 } }
    ];
    
    const reportData = [];
    const cursor = misCollection.aggregate(pipeline);
    
    for await (const row of cursor) {
      reportData.push({
        recruiter_name: row._id,
        total_resumes: row.total_resumes,
        shortlisted: row.shortlisted,
        rejected: row.rejected
      });
    }
    
    const dateFormatted = formatDateWithDay(startDate);
    
    res.json({
      date: dateFormatted,
      date_type: date_type,
      reports: reportData
    });
  } catch (error) {
    console.error('Reports by date error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Root
app.get('/', (req, res) => {
  res.json({ message: 'Backend is live!' });
});

// 404 JSON handler
app.use((req, res, next) => {
  res.status(404).json({ detail: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ detail: 'Internal server error' });
});

// Start server
const startServer = async () => {
  await connectToDatabase();
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
  });
};

startServer().catch(console.error);

module.exports = app;
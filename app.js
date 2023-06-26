const fs = require('fs');
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const mysql = require('mysql2')
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const multer = require('multer');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const router = express()

//buat folder penampung file jika tidak ada
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}


router.set('view engine', 'ejs')
router.set('views', path.join(__dirname, 'views'))
router.set('views', './views');
router.use(expressLayouts)
router.use('/css', express.static(path.resolve(__dirname, "public/css")));
router.use('/img', express.static(path.resolve(__dirname, "public/img")));


// middleware untuk parsing request body
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
router.use(cookieParser());

//saltround
const saltRounds = 10;

// untuk konfigurasi storage 
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

// konfigurasi upload
const upload = multer({ storage: storage });

// koneksi database
const db = mysql.createConnection({
  host: 'sql.freedb.tech',
  user: 'freedb_reviputra',
  database: 'freedb_tbpwebarevi',
  password:'DJXJ!xkZnA88fKB'
});

//cek apakah sudah konek, kalau belum kasih info error
db.connect((err)=>{
  if(err) throw err
  console.log('database terkoneksi')
})

//GET 
router.get('/login', function (req, res) {
  res.render('login',{
    title:'login',
    layout:'layouts/auth-layout'
  })
})

router.get('/register', function (req, res) {
  res.render('register',{
    title:'register',
    layout:'layouts/auth-layout'
  })
})

// index page
router.get('/', requireAuth, function (req, res) {
  if (!req.user_id) {
    res.redirect('/login');
    return;
  }

  const user_id = req.user_id;

  const selectUserSql = `SELECT * FROM users WHERE user_id = ${user_id}`;

  db.query(selectUserSql, (err, userResult) => {
    if (err) {
      throw err;
    }

    const selectSql = `SELECT users.*, forms.*
    FROM users 
    JOIN forms ON users.user_id = forms.user_id
    `;

    db.query(selectSql, (err, result) => {
      if (err) {
        throw err;
      }
      res.render('index', {
        user: userResult[0], 
        forms: result,
        moment: moment,
        title: 'Dashboard',
        layout: 'layouts/main-layout'
      });
    });
  });
});


router.get('/add-form', function (req, res) {
  res.render('add-form',{
    title:'add form',
    layout:'layouts/main-layout'
  })
})

router.get('/submit-course/:form_id', requireAuth, function(req, res) {
  const user_id = req.user_id;
  const form_id = req.params.form_id;

  // check if user is the creator of the form
  const formSql = 'SELECT * FROM forms WHERE form_id = ?';
  db.query(formSql, [form_id], function (err, formResult) {
    if (err) throw err;

    const formCreator = formResult[0].user_id;
    if (user_id === formCreator) {
      res.json('Cannot submit own course');
      return;
    }

    // check if user has submitted the form
    const submissionSql =
      'SELECT * FROM submissions WHERE form_id = ? AND user_id = ?';
    db.query(submissionSql, [form_id, user_id], function (
      err,
      submissionResult
    ) {
      if (err) throw err;

      let isSubmitted = false;
      let submission = null;

      if (submissionResult.length > 0) {
        isSubmitted = true;
        submission = submissionResult[0];
      }

      const selectUserSql = `SELECT * FROM users WHERE user_id = ${user_id}`;

      db.query(selectUserSql, function (err, userResult) {
        if (err) throw err;

        res.render('submit-course', {
          user: userResult[0],
          form: formResult[0],
          moment:moment,
          title: 'Submit course',
          layout: 'layouts/main-layout',
          isSubmitted: isSubmitted,
          submission: submission
        });
      });
    });
  });
});


router.get('/about-us', requireAuth, function (req, res) {
  const user_id = req.user_id;
  const selectSql = `SELECT * FROM users WHERE user_id = ${user_id}`;
  db.query(selectSql, (err,result)=>{
    if (err) throw err;
      res.render('about-us',{
        user:result[0],
        title:'About us',
        layout:'layouts/main-layout'
      });
  });
})

router.get('/edit-profil', requireAuth, function (req, res) {
  const user_id = req.user_id;
  const selectSql = `SELECT * FROM users WHERE user_id = ${user_id}`;
  db.query(selectSql, (err,result)=>{
    if (err) throw err;
      res.render('edit-profil',{
        user:result[0],
        title:'Edit Profil',
        layout:'layouts/main-layout'
      });
  });
})

router.get('/ganti-password', requireAuth, function (req, res) {
  const user_id = req.user_id;
  const selectSql = `SELECT * FROM users WHERE user_id = ${user_id}`;
  db.query(selectSql, (err,result)=>{
    if (err) throw err;
      res.render('ganti-password',{
        user:result[0],
        title:'Ganti password',
        layout:'layouts/main-layout'
      });
  });
})

//profil page
router.get('/profil', requireAuth, function (req, res) {
  // const successMessage = req.session.successMessage;
  // const errorMessage = req.session.errorMessage; // Menambahkan errorMessage
  // delete req.session.successMessage;
  // delete req.session.errorMessage; // Menghapus errorMessage setelah digunakan
  let user_id = req.user_id;
  const selectSql = `SELECT * FROM users WHERE user_id = ${user_id}`;
  db.query(selectSql, (err,result)=>{
    if (err) throw err;
    // Periksa apakah user sudah login dan aktif
    if (result[0].active === 0) {
      res.render('profil',{
        user: result[0],
        title:'Profil',
        layout:'layouts/main-layout',
        // successMessage: successMessage,
        // errorMessage: errorMessage 
      });
    } else {
      // Jika user tidak aktif, arahkan kembali ke halaman login
      res.redirect('/login');
    }
  });
});


//POST
//register
router.post('/register', function (req, res) {
  const { username, password, confirm_password } = req.body;

  
  const sqlCheck = 'SELECT * FROM users WHERE username = ?';
  db.query(sqlCheck, username, (err, result) => {
    if (err) throw err;

    if (result.length > 0) {
      // cek username sudah terdaftar atau belum
      return res.status(400).send('username sudah terdaftar');
    }

    if (password !== confirm_password) {
      //mencocokan password
      return res.status(400).send('password tidak cocok!');
    }

    // menghash password
    bcrypt.hash(password, saltRounds, function(err, hash) {
      if (err) throw err;

      // tambahkan user ke database
      const sqlInsert = 'INSERT INTO users (username, password) VALUES (?, ?)';
      const values = [username, hash];
      db.query(sqlInsert, values, (err, result) => {
        if (err) throw err;
        console.log('user terdaftar!');
        res.redirect('/login');
      });
    });
  });
});

//login
router.post('/login', function (req, res) {
  const { username, password } = req.body;

    const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], function(err, result) {
      if (err) throw err;

      if (result.length === 0) {
          res.status(401).send('Invalid username or password');
          return;
      }

      const user = result[0];

      // compare password
      bcrypt.compare(password, user.password, function(err, isValid) {
          if (err) throw err;

          if (!isValid) {
              res.status(401).send('Invalid username or password');
              return;
          }

          // generate token
          const token = jwt.sign({ user_id: user.user_id }, 'secret_key');
          res.cookie('token', token, { httpOnly: true });

          res.redirect('/');
      });
   });
});

router.post('/buat-form', requireAuth, function (req, res) {
  
  const user_id = req.user_id;
  const title = req.body.title;
  const description = req.body.description;

  const sql = 'INSERT INTO forms (user_id, title, description) VALUES ( ?, ?, ?)';
  const values = [user_id, title, description];
  db.query(sql, values, (err, result) => {
    if (err) {
      throw err;
    }
    console.log({ message: 'Form berhasil dibuat', values });
    res.redirect('/');
  });
});

router.post('/submit-course', upload.single('uploaded_file'), requireAuth, (req, res) => {
  const { user_id, form_id, description } = req.body;
  const uploaded_file = req.file.filename;

  // Check if user has already submitted for the form
  const submissionSql = `SELECT * FROM submissions WHERE user_id = ? AND form_id = ?`;
  const submissionValues = [user_id, form_id];
  db.query(submissionSql, submissionValues, (err, submissionResult) => {
    if (err) {
      throw err;
    }

    // Insert data to MySQL
    const insertSql = `INSERT INTO submissions (user_id, form_id, uploaded_file, description) VALUES (?, ?, ?, ?)`;
    const insertValues = [user_id, form_id, uploaded_file, description];
    db.query(insertSql, insertValues, (err, result) => {
      if (err) {
        throw err;
      }
      console.log('Data inserted to MySQL!');
      res.redirect('/');
    });
  });
});

router.post('/edit-profil', upload.single('avatar'), requireAuth, (req, res) => {
  let user_id = req.user_id;
  const { email, about_me } = req.body;
  const avatar = req.file.filename;

  // Insert data to MySQL
  const updateUserSql = `UPDATE users SET email=?, avatar=?, about_me=? WHERE user_id=${user_id}`;
  const values = [email, avatar, about_me];
  db.query(updateUserSql, values, (err, result) => {
    if (err) {
      throw err;
    }
    console.log({msg:'Data inserted to MySQL!',values});
    // Copy file to img directory
    const source = path.join(__dirname, 'uploads', avatar);
    const destination = path.join(__dirname, 'public', 'img', avatar);
    fs.copyFileSync(source, destination);

    res.redirect('/profil');
  });
});

router.post('/ganti-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;
  const userId = req.user_id;

  // Check if current password matches with database
  const sql = 'SELECT password FROM users WHERE user_id = ?';
  db.query(sql, [userId], (err, result) => {
    if (err) {
      console.log({ message: 'Internal Server Error', err });
      res.redirect('/profil');
      return;
    }

    const hashedPassword = result[0].password;
    bcrypt.compare(currentPassword, hashedPassword, (error, isMatch) => {
      if (error) {
        console.log({ message: 'Internal Server Error', error });
        res.redirect('/profil');
        return;
      }

      if (isMatch) {
        // If current password matches, check if new password and confirm new password match
        if (newPassword === confirmNewPassword) {
          // Hash new password and update database
          bcrypt.hash(newPassword, saltRounds, (err, hashedNewPassword) => {
            if (err) {
              console.log({ message: 'Internal Server Error', err });
              res.redirect('/profil');
              return;
            }

            const updateSql = 'UPDATE users SET password = ? WHERE user_id = ?';
            const values = [hashedNewPassword, userId];
            db.query(updateSql, values, (err, result) => {
              if (err) {
                console.log({ message: 'Internal Server Error', err });
                res.redirect('/profil');
                return;
              }
              console.log({ message: 'Password berhasil diubah', values });
              res.redirect('/profil');
            });
          });
        } else {
          // If new password and confirm new password don't match, send error message
          console.log({ message: 'New password and confirm new password do not match' });
          res.redirect('/profil');
        }
      } else {
        // If current password doesn't match, send error message
        console.log({ message: 'Invalid current password' });
        res.redirect('/profil');
      }
    });
  });
});


router.get('/download/:user_id/:form_id', requireAuth, (req, res) => {
  const userId = req.params.user_id;
  const formId = req.params.form_id;

  // check if user has access to the form
  const formSql = 'SELECT * FROM forms WHERE form_id = ?';
  db.query(formSql, [formId], function(err, formResult) {
    if (err) throw err;
    if (formResult.length === 0) {
      res.status(404).send('Form not found');
      return;
    }

    // check if submission exists
    const submissionSql = 'SELECT * FROM submissions WHERE user_id = ? AND form_id = ?';
    db.query(submissionSql, [userId, formId], function(err, submissionResult) {
      if (err) throw err;
      if (submissionResult.length === 0) {
        res.status(404).send('Submission not found');
        return;
      }

      const submission = submissionResult[0];
      const filePath = `uploads/${submission.uploaded_file}`;

      res.download(filePath, submission.file_name, function(err) {
        if (err) {
          console.log(err);
          res.status(500).send('Internal server error');
        }
      });
    });
  });
});



// middleware untuk memeriksa apakah user sudah login atau belum
function requireAuth(req, res, next) {
  
  const token = req.cookies.token;

  if (!token) {
    res.redirect('/login');
    return;
  }
  

  jwt.verify(token, 'secret_key', function(err, decoded) {
    if (err) {
      res.redirect('/login');
      return;
    }

    req.user_id = decoded.user_id;
    next();
  });
}





router.listen(3000,(req, res) => {
  console.log('listening on port 3000')
})
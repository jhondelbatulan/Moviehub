# Bike Rental/Reservation System

A complete web-based bike rental system built with HTML, CSS, JavaScript, PHP, and MySQL.

## 🚀 Features

### Client Features
- **User Registration & Login**: Secure user authentication with password hashing
- **Dashboard**: View available bikes with real-time availability
- **Bike Rental Requests**: Submit rental requests with date selection
- **Profile Management**: Update personal information and change password
- **Notification System**: Track rental request status
- **Responsive Design**: Works on desktop and mobile devices

### Admin Features
- **Admin Dashboard**: Overview of system statistics
- **Bike Management**: Add, edit, and delete bikes from inventory
- **Rental Request Management**: Approve or deny rental requests
- **User Management**: View all registered users
- **Advanced Filtering**: Search and filter rental requests

## 🛠️ Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript
- **Backend**: PHP 7.4+
- **Database**: MySQL 5.7+
- **Server**: XAMPP (Apache, MySQL, PHP)
- **Styling**: Custom CSS with modern design
- **Icons**: Font Awesome 6.0

## 📁 Project Structure

```
final/
├── index.php                 # Main landing page
├── db_connect.php            # Database connection
├── database_schema.sql       # Database schema
├── assets/
│   └── css/
│       └── style.css         # Main stylesheet
├── client/                   # Client-side pages
│   ├── login.php
│   ├── register.php
│   ├── dashboard.php
│   ├── profile.php
│   └── logout.php
└── admin/                    # Admin-side pages
    ├── login.php
    ├── dashboard.php
    ├── manage_bikes.php
    ├── rental_requests.php
    └── logout.php
```

## 🗄️ Database Schema

### Tables
1. **users** - Client account information
2. **admin_users** - Admin account information
3. **bikes** - Bike inventory management
4. **rental_requests** - Rental request tracking

## 🚀 Installation & Setup

### Prerequisites
- XAMPP installed and running
- PHP 7.4 or higher
- MySQL 5.7 or higher

### Setup Steps

1. **Clone/Download the project**
   ```bash
   # Place the project in your XAMPP htdocs folder
   # Path: C:\xampp\htdocs\final\
   ```

2. **Start XAMPP Services**
   - Start Apache and MySQL services in XAMPP Control Panel

3. **Create Database**
   - Open phpMyAdmin (http://localhost/phpmyadmin)
   - Import the `database_schema.sql` file to create the database and tables
   - Or manually run the SQL commands from the schema file

4. **Configure Database Connection**
   - Edit `db_connect.php` if needed to match your MySQL credentials
   - Default settings should work with XAMPP:
     - Host: localhost
     - Database: bike_rental_system
     - Username: root
     - Password: (empty)

5. **Access the Application**
   - Open your browser and navigate to: `http://localhost/final/`

## 👥 Default Credentials

### Admin Login
- **Username**: admin
- **Password**: admin123

### Client Registration
- Users need to register first before they can login
- Registration includes username, email, full name, contact, and address

## 🎯 Usage Guide

### For Clients
1. **Register**: Create a new account on the registration page
2. **Login**: Use your credentials to access the dashboard
3. **Browse Bikes**: View available bikes with details and pricing
4. **Request Rental**: Click "Rent/Reserve" to submit a rental request
5. **Track Status**: Monitor your rental requests in the dashboard
6. **Update Profile**: Modify your personal information as needed

### For Admins
1. **Login**: Use admin credentials to access the admin panel
2. **Dashboard**: View system statistics and recent requests
3. **Manage Bikes**: Add, edit, or remove bikes from inventory
4. **Process Requests**: Approve or deny rental requests
5. **Monitor System**: Track all user activities and requests

## 🔧 Key Features Explained

### Security
- Password hashing using PHP's `password_hash()` function
- Session-based authentication
- SQL injection prevention with prepared statements
- Input validation and sanitization

### User Experience
- Responsive design that works on all devices
- Real-time form validation
- Modal dialogs for better user interaction
- Status badges for easy status identification
- Search and filter functionality

### Admin Features
- Comprehensive dashboard with statistics
- Bulk operations for bike management
- Advanced filtering for rental requests
- Admin notes for request decisions

## 🎨 Design Features

- **Modern UI**: Clean and professional design
- **Gradient Backgrounds**: Eye-catching color schemes
- **Card-based Layout**: Organized content presentation
- **Responsive Grid**: Adapts to different screen sizes
- **Interactive Elements**: Hover effects and animations
- **Status Indicators**: Color-coded status badges

## 🔍 File Descriptions

- `index.php`: Landing page with access to client and admin sections
- `db_connect.php`: Database connection configuration
- `database_schema.sql`: Complete database structure with sample data
- `client/login.php`: Client authentication page
- `client/register.php`: New user registration
- `client/dashboard.php`: Main client interface with bike listings
- `client/profile.php`: User profile management
- `admin/login.php`: Admin authentication page
- `admin/dashboard.php`: Admin overview with statistics
- `admin/manage_bikes.php`: Bike inventory management
- `admin/rental_requests.php`: Rental request processing
- `assets/css/style.css`: Complete styling for the entire application

## 🚨 Important Notes

1. **Password Security**: The default admin password should be changed in production
2. **File Permissions**: Ensure proper file permissions for uploads (if implemented)
3. **Database Backup**: Regularly backup your database
4. **Error Handling**: The system includes comprehensive error handling
5. **Validation**: All forms include client-side and server-side validation

## 🔮 Future Enhancements

- Image upload for bikes
- Payment integration
- Email notifications
- Advanced reporting
- Mobile app integration
- GPS tracking for bikes
- Multi-language support

## 📞 Support

For any issues or questions:
1. Check the database connection settings
2. Ensure XAMPP services are running
3. Verify file permissions
4. Check browser console for JavaScript errors

---

**Built with ❤️ for bike rental management**

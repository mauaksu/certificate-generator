def ensure_proper_pem_format(input_path, output_path):
    """Ensure proper PEM format by explicitly converting through OpenSSL"""
    try:
        # Check if input file exists
        if not os.path.exists(input_path):
            app.logger.error(f"Input file not found: {input_path}")
            return False
            
        # Convert to proper PEM format
        cmd = [
            'openssl', 'x509',
            '-in', input_path,
            '-out', output_path,
            '-outform', 'PEM'
        ]
        
        subprocess.run(cmd, check=True)
        
        # Verify the file is in proper PEM format
        with open(output_path, 'r') as f:
            content = f.read()
            
        # Check for PEM begin and end markers
        if not ('-----BEGIN CERTIFICATE-----' in content and '-----END CERTIFICATE-----' in content):
            app.logger.error(f"Generated file is not in proper PEM format: {output_path}")
            return False
            
        return True
    except subprocess.CalledProcessError as e:
        app.logger.error(f"OpenSSL error during PEM conversion: {e.stderr if hasattr(e, 'stderr') else str(e)}")
        return False
    except Exception as e:
        app.logger.error(f"Error ensuring PEM format: {str(e)}")
        return False

import os
import uuid
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload
app.secret_key = os.urandom(24)

# Ensure upload and result directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pfx', 'p12', 'pem', 'crt', 'key', 'csr', 'conf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_certificate():
    # CSR is now the only input method
    input_method = 'csr'
    
    # Get CA input method
    ca_input_method = request.form.get('ca_input_method', 'separate')
    
    # Check for CA files based on input method
    ca_cert_path = None
    ca_key_path = None
    ca_password = request.form.get('ca_password', '')
    
    # Generate unique session ID
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    os.makedirs(session_dir, exist_ok=True)
    
    try:
        # Process CA files based on input method
        if ca_input_method == 'separate':
            # Check if CA certificate and key files are provided
            if 'ca_cert' not in request.files or 'ca_key' not in request.files:
                flash('Missing CA certificate or key files')
                return redirect(url_for('index'))
                
            ca_cert = request.files['ca_cert']
            ca_key = request.files['ca_key']
            
            # Check if CA files are selected
            if ca_cert.filename == '' or ca_key.filename == '':
                flash('No CA files selected')
                return redirect(url_for('index'))
                
            # Check CA file types
            if not (allowed_file(ca_cert.filename) and allowed_file(ca_key.filename)):
                flash('Invalid CA file type. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS))
                return redirect(url_for('index'))
                
            # Save CA files
            ca_cert_path = os.path.join(session_dir, secure_filename(ca_cert.filename))
            ca_key_path = os.path.join(session_dir, secure_filename(ca_key.filename))
            ca_cert.save(ca_cert_path)
            ca_key.save(ca_key_path)
            
        else:  # PFX input method
            # Check if CA PFX file is provided
            if 'ca_pfx' not in request.files:
                flash('Missing CA PFX file')
                return redirect(url_for('index'))
                
            ca_pfx = request.files['ca_pfx']
            
            # Check if CA PFX file is selected
            if ca_pfx.filename == '':
                flash('No CA PFX file selected')
                return redirect(url_for('index'))
                
            # Check CA PFX file type
            if not allowed_file(ca_pfx.filename):
                flash('Invalid CA PFX file type')
                return redirect(url_for('index'))
                
            # Save CA PFX file
            ca_pfx_path = os.path.join(session_dir, secure_filename(ca_pfx.filename))
            ca_pfx.save(ca_pfx_path)
            
            # Extract certificate and key from PFX
            ca_cert_path = os.path.join(session_dir, 'root.cer')
            ca_key_path = os.path.join(session_dir, 'root.key')
            
            # Extract certificate
            cert_cmd = [
                'openssl', 'pkcs12', '-in', ca_pfx_path, 
                '-passin', f'pass:{ca_password}', 
                '-nokeys', '-out', ca_cert_path
            ]
            
            cert_result = subprocess.run(cert_cmd, capture_output=True, text=True)
            if cert_result.returncode != 0:
                flash(f'Error extracting certificate from PFX: {cert_result.stderr}')
                return redirect(url_for('index'))
                
            # Extract private key
            key_cmd = [
                'openssl', 'pkcs12', '-in', ca_pfx_path, 
                '-passin', f'pass:{ca_password}', 
                '-nocerts', '-out', ca_key_path,
                '-nodes'  # No encryption on the output key
            ]
            
            key_result = subprocess.run(key_cmd, capture_output=True, text=True)
            if key_result.returncode != 0:
                flash(f'Error extracting private key from PFX: {key_result.stderr}')
                return redirect(url_for('index'))
        
        # Get common form data
        signing_method = request.form.get('signing_method', 'x509')
        
        # Get validity days based on signing method
        if signing_method == 'x509':
            validity_days = request.form.get('validity_days', '365')
        else:
            validity_days = request.form.get('ca_validity_days', '7320')
    
        # Output path for cross-signed certificate (as PEM format)
        output_filename = f"cross-signed-{session_id}.pem"
        output_path = os.path.join(app.config['RESULT_FOLDER'], output_filename)
        
        # Process CSR input
        if 'csr_file' not in request.files:
            flash('Missing CSR file')
            return redirect(url_for('index'))
        
        csr_file = request.files['csr_file']
        
        if csr_file.filename == '':
            flash('No CSR file selected')
            return redirect(url_for('index'))
        
        if not allowed_file(csr_file.filename):
            flash('Invalid CSR file type')
            return redirect(url_for('index'))
        
        csr_path = os.path.join(session_dir, secure_filename(csr_file.filename))
        csr_file.save(csr_path)
        
        # For the purpose of the myca.conf, rename the CSR to expected name
        if signing_method == 'ca':
            iag_ca_csr_path = os.path.join(session_dir, 'iag_ca.csr')
            import shutil
            shutil.copy2(csr_path, iag_ca_csr_path)
            csr_path = iag_ca_csr_path
        
        # Process the CSR file based on signing method
        if signing_method == 'x509':
            # Standard x509 signing
            process_result = process_csr(
                csr_path,
                ca_cert_path,
                ca_key_path,
                ca_password,
                output_path,
                validity_days
            )
        else:
            # CA signing with config
            if 'ca_config' not in request.files:
                flash('Missing CA configuration file')
                return redirect(url_for('index'))
            
            ca_config = request.files['ca_config']
            
            if ca_config.filename == '':
                flash('No CA configuration file selected')
                return redirect(url_for('index'))
            
            if not allowed_file(ca_config.filename):
                flash('Invalid CA config file type')
                return redirect(url_for('index'))
            
            # Save CA config file as myca.conf
            ca_config_path = os.path.join(session_dir, 'myca.conf')
            ca_config.save(ca_config_path)
            
            # Get additional options
            ca_batch = 'ca_batch' in request.form
            ca_notext = 'ca_notext' in request.form
            
            # Process with CA command
            process_result = process_csr_with_ca(
                csr_path,
                ca_cert_path,
                ca_key_path,
                ca_password,
                ca_config_path,
                output_path,
                validity_days,
                ca_batch,
                ca_notext
            )
        
        # Final verification of PEM format
        if process_result:
            temp_verified_path = os.path.join(session_dir, 'verified.pem')
            verify_result = ensure_proper_pem_format(output_path, temp_verified_path)
            
            if verify_result:
                # Replace the output with the verified version
                import shutil
                shutil.move(temp_verified_path, output_path)
            else:
                process_result = False
        
        if process_result:
            # Clean up uploaded files
            for file_path in os.listdir(session_dir):
                os.remove(os.path.join(session_dir, file_path))
            os.rmdir(session_dir)
            
            return redirect(url_for('download_result', filename=output_filename))
        else:
            flash('Error processing certificate. Please check your files and passwords.')
            return redirect(url_for('index'))
            
    except Exception as e:
        flash(f'Error: {str(e)}')
        return redirect(url_for('index'))

def process_pfx(pfx_path, pfx_password, ca_cert_path, ca_key_path, ca_password, output_path, validity_days):
    # Create a temporary directory for processing
    temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + str(uuid.uuid4()))
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        # Extract certificate from PFX
        cert_pem = os.path.join(temp_dir, 'cert.pem')
        cmd = [
            'openssl', 'pkcs12', '-in', pfx_path, 
            '-passin', f'pass:{pfx_password}', 
            '-nokeys', '-out', cert_pem
        ]
        subprocess.run(cmd, check=True)
        
        # Extract private key from PFX
        key_pem = os.path.join(temp_dir, 'key.pem')
        private_key = os.path.join(temp_dir, 'private.key')
        
        cmd = [
            'openssl', 'pkcs12', '-in', pfx_path, 
            '-passin', f'pass:{pfx_password}', 
            '-nocerts', '-out', key_pem,
            '-passout', 'pass:temp'
        ]
        subprocess.run(cmd, check=True)
        
        cmd = [
            'openssl', 'rsa', '-in', key_pem,
            '-passin', 'pass:temp',
            '-out', private_key
        ]
        subprocess.run(cmd, check=True)
        
        # Get subject from certificate
        proc = subprocess.run(
            ['openssl', 'x509', '-in', cert_pem, '-noout', '-subject'],
            capture_output=True, text=True, check=True
        )
        subject = proc.stdout.strip().replace('subject= ', '')
        
        # Create CSR
        csr_path = os.path.join(temp_dir, 'request.csr')
        cmd = [
            'openssl', 'req', '-new',
            '-key', private_key,
            '-out', csr_path,
            '-subj', subject
        ]
        subprocess.run(cmd, check=True)
        
        # Cross-sign the CSR
        ca_serial = os.path.join(temp_dir, 'ca.srl')
        cmd = [
            'openssl', 'x509', '-req',
            '-in', csr_path,
            '-CA', ca_cert_path,
            '-CAkey', ca_key_path,
            '-CAcreateserial',
            '-out', output_path,
            '-days', validity_days,
            '-outform', 'PEM'  # Explicitly specify PEM output format
        ]
        
        if ca_password:
            cmd.extend(['-passin', f'pass:{ca_password}'])
            
        subprocess.run(cmd, check=True)
        
        return True
    except subprocess.CalledProcessError as e:
        app.logger.error(f"OpenSSL error: {e.stderr if hasattr(e, 'stderr') else str(e)}")
        return False
    finally:
        # Clean up temporary files
        for file in os.listdir(temp_dir):
            os.remove(os.path.join(temp_dir, file))
        os.rmdir(temp_dir)

@app.route('/download/<filename>')
def download_result(filename):
    return render_template('download.html', filename=filename)

def process_csr(csr_path, ca_cert_path, ca_key_path, ca_password, output_path, validity_days):
    """Process a CSR file and generate a cross-signed certificate using x509 in PEM format"""
    try:
        # Create a temporary file for the initial certificate
        temp_cert = os.path.join(os.path.dirname(output_path), 'temp_cert.der')
        
        # Cross-sign the CSR
        cmd = [
            'openssl', 'x509', '-req',
            '-in', csr_path,
            '-CA', ca_cert_path,
            '-CAkey', ca_key_path,
            '-CAcreateserial',
            '-out', temp_cert,
            '-days', validity_days
        ]
        
        if ca_password:
            cmd.extend(['-passin', f'pass:{ca_password}'])
            
        subprocess.run(cmd, check=True)
        
        # Explicitly convert to PEM format
        convert_cmd = [
            'openssl', 'x509',
            '-in', temp_cert,
            '-out', output_path,
            '-outform', 'PEM'
        ]
        
        subprocess.run(convert_cmd, check=True)
        
        # Verify the PEM format
        verify_cmd = [
            'openssl', 'x509',
            '-in', output_path,
            '-inform', 'PEM',
            '-noout',
            '-text'
        ]
        
        verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
        if verify_result.returncode != 0:
            app.logger.error(f"PEM verification failed: {verify_result.stderr}")
            return False
            
        # Remove temporary file
        if os.path.exists(temp_cert):
            os.remove(temp_cert)
            
        return True
    except subprocess.CalledProcessError as e:
        app.logger.error(f"OpenSSL error: {e.stderr if hasattr(e, 'stderr') else str(e)}")
        return False
    except Exception as e:
        app.logger.error(f"Error in CSR processing: {str(e)}")
        return False

def process_csr_with_ca(csr_path, ca_cert_path, ca_key_path, ca_password, ca_config_path, output_path, validity_days, batch=True, notext=True):
    """Process a CSR file using openssl ca command with config file to produce a PEM certificate"""
    try:
        # Create working directory for CA operations
        ca_dir = os.path.dirname(ca_config_path)
        
        # Create necessary directories
        os.makedirs(os.path.join(ca_dir, 'newcerts'), exist_ok=True)
        
        # Create symbolic links or copy CA cert and key to expected locations
        # First, read the config file to find the expected file names
        with open(ca_config_path, 'r') as f:
            config_content = f.read()
        
        # Find the certificate and private key paths in the config
        import re
        cert_match = re.search(r'certificate\s*=\s*(.+)', config_content)
        key_match = re.search(r'private_key\s*=\s*(.+)', config_content)
        db_match = re.search(r'database\s*=\s*(.+)', config_content)
        serial_match = re.search(r'serial\s*=\s*(.+)', config_content)
        
        # Get the expected file names (or use defaults)
        cert_name = cert_match.group(1).strip() if cert_match else 'cacert.pem'
        key_name = key_match.group(1).strip() if key_match else 'cakey.pem'
        db_name = db_match.group(1).strip() if db_match else 'index.txt'
        serial_name = serial_match.group(1).strip() if serial_match else 'serial'
        
        # Create symbolic links or copy files
        cert_target = os.path.join(ca_dir, cert_name)
        key_target = os.path.join(ca_dir, key_name)
        db_path = os.path.join(ca_dir, db_name)
        serial_path = os.path.join(ca_dir, serial_name)
        
        # Copy CA certificate and key to expected locations
        import shutil
        shutil.copy2(ca_cert_path, cert_target)
        shutil.copy2(ca_key_path, key_target)
        
        # Create database file if it doesn't exist
        if not os.path.exists(db_path):
            with open(db_path, 'w') as f:
                pass
        
        # Create serial file if it doesn't exist
        if not os.path.exists(serial_path):
            with open(serial_path, 'w') as f:
                f.write('01')
        
        # Build the openssl ca command
        cmd = [
            'openssl', 'ca',
            '-config', ca_config_path,
            '-in', csr_path,
            '-out', output_path,
            '-days', validity_days
        ]
        
        # Add optional arguments
        if batch:
            cmd.append('-batch')
        
        if notext:
            cmd.append('-notext')
        
        if ca_password:
            cmd.extend(['-passin', f'pass:{ca_password}'])
        
        # Run the command with detailed error capturing
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check for errors
        if process.returncode != 0:
            app.logger.error(f"OpenSSL CA error: {process.stderr}")
            return False
        
        return True
    except Exception as e:
        app.logger.error(f"Error in CA processing: {str(e)}")
        return False

@app.route('/get_file/<filename>')
def get_file(filename):
    return send_from_directory(app.config['RESULT_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
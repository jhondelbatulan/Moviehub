<?php
// Shared blocking "Complete Your Account" modal.
// Requires the including page to set before include:
//   $cp_row (assoc), $cp_is_admin (bool), $cp_ajax (relative url), $cp_title (string),
//   $cp_first/$cp_last/$cp_middle/$cp_sex/$cp_birthdate/$cp_email/$cp_contact/$cp_address (prefill strings)
// The page must already have called generate_csrf_token().
$cp_title = $cp_title ?? 'Complete Your Account Information';
$cp_sex = $cp_sex ?? '';
$cp_birthdate = $cp_birthdate ?? '';
$cp_email = $cp_email ?? '';
$cp_contact = $cp_contact ?? '';
$cp_address = $cp_address ?? '';
?>
<div id="completeProfileModal" class="modal" style="display:flex;background:rgba(10,14,22,0.85);backdrop-filter:blur(3px);z-index:2000;">
    <div class="modal-content" style="max-width:640px;width:100%;max-height:92vh;overflow-y:auto;">
        <div class="modal-header">
            <h3 class="modal-title"><i class="fas fa-user-edit" style="margin-right:0.5rem;"></i> <?php echo htmlspecialchars($cp_title); ?></h3>
        </div>
        <div class="modal-body">
            <p style="font-size:0.8125rem;color:var(--text-light);margin-bottom:1rem;">Please complete your account information to finish setting up your account. Age is computed automatically from your birth date.</p>
            <div id="cpError" class="alert alert-danger" style="display:none;"></div>
            <form id="cpForm" novalidate>
                <?php csrf_token_input(); ?>
                <div class="form-row">
                    <div class="form-group">
                        <label>First Name *</label>
                        <input type="text" id="cp_first" name="first_name" class="form-control" required maxlength="30" value="<?php echo htmlspecialchars($cp_first); ?>" autocomplete="off">
                        <small class="cp-status"></small>
                    </div>
                    <div class="form-group">
                        <label>Middle Initial</label>
                        <input type="text" id="cp_middle" name="middle_initial" class="form-control" maxlength="1" placeholder="e.g., M" value="<?php echo htmlspecialchars($cp_middle); ?>" oninput="this.value=this.value.toUpperCase()" autocomplete="off">
                        <small class="cp-status"></small>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Last Name *</label>
                        <input type="text" id="cp_last" name="last_name" class="form-control" required maxlength="30" value="<?php echo htmlspecialchars($cp_last); ?>" autocomplete="off">
                        <small class="cp-status"></small>
                    </div>
                    <div class="form-group">
                        <label>Gender *</label>
                        <select name="sex" id="cp_sex" class="form-control" required>
                            <option value="">-- Select --</option>
                            <option value="Male" <?php echo $cp_sex === 'Male' ? 'selected' : ''; ?>>Male</option>
                            <option value="Female" <?php echo $cp_sex === 'Female' ? 'selected' : ''; ?>>Female</option>
                            <option value="Prefer not to say" <?php echo $cp_sex === 'Prefer not to say' ? 'selected' : ''; ?>>Prefer not to say</option>
                        </select>
                        <small class="cp-status"></small>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Birth Date *</label>
                        <input type="date" id="cp_birthdate" name="birthdate" class="form-control" required max="<?php echo date('Y-m-d'); ?>" value="<?php echo htmlspecialchars($cp_birthdate); ?>">
                        <small class="cp-status"></small>
                    </div>
                    <div class="form-group">
                        <label>Age</label>
                        <input type="text" id="cp_age" class="form-control" readonly value="" placeholder="Auto">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Email *</label>
                        <input type="email" id="cp_email" name="email" class="form-control" required value="<?php echo htmlspecialchars($cp_email); ?>">
                        <small class="cp-status"></small>
                    </div>
                    <div class="form-group">
                        <label>Contact Number *</label>
                        <input type="text" id="cp_contact" name="contact_number" class="form-control" required placeholder="e.g., 0917-123-4567" value="<?php echo htmlspecialchars($cp_contact); ?>">
                        <small class="cp-status"></small>
                    </div>
                </div>
                <div class="form-group">
                    <label>Address</label>
                    <textarea name="address" id="cp_address" class="form-control" rows="2" placeholder="Street, Barangay, City, Province, Zip"><?php echo htmlspecialchars($cp_address); ?></textarea>
                </div>

                <div class="divider"></div>
                <h4 style="margin-bottom:0.75rem;"><i class="fas fa-lock"></i> Account Credentials</h4>
                <div class="form-row">
                    <div class="form-group">
                        <label>New Password (optional)</label>
                        <input type="password" id="cp_newp" name="new_password" class="form-control" minlength="8" maxlength="30" autocomplete="new-password">
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password</label>
                        <input type="password" id="cp_cnfp" name="confirm_password" class="form-control" minlength="8" maxlength="30" autocomplete="new-password">
                    </div>
                </div>
                <small style="font-size:0.75rem;color:var(--muted);">Leave blank to keep your current password.</small>

                <button type="submit" class="btn btn-primary" style="width:100%;margin-top:1rem;" id="cpSubmit">
                    <i class="fas fa-check"></i> Save &amp; Continue
                </button>
            </form>
        </div>
    </div>
</div>
<script>
(function () {
    var modal = document.getElementById('completeProfileModal');
    var form = document.getElementById('cpForm');
    var errBox = document.getElementById('cpError');
    var submitBtn = document.getElementById('cpSubmit');

    function nameOk(v) {
        v = v.trim();
        if (!v) return false;
        if (v.length < 2 || v.length > 30) return false;
        if (!/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/.test(v)) return false;
        if (/^[A-Z]+$/.test(v)) return false;
        if (/[0-9]/.test(v) || /[^A-Za-z ]/.test(v)) return false;
        if (/(.)\1{2,}/.test(v)) return false;
        return true;
    }
    function phOk(v) {
        v = v.trim();
        var n = v.replace(/[^0-9]/g, '');
        if (n.indexOf('63') === 0) n = n.substring(2);
        if (n.indexOf('0') === 0) n = n.substring(1);
        return /^9\d{9}$/.test(n);
    }
    function addrOk(v) {
        v = v.trim();
        if (!v) return true;
        if (v.length < 2 || v.length > 100) return false;
        return /^[A-Za-z0-9][A-Za-z0-9 .,'#-]*$/.test(v) && /[A-Za-z]/.test(v);
    }

    document.getElementById('cp_birthdate').addEventListener('input', function () {
        var d = this.value, ageEl = document.getElementById('cp_age');
        if (d) {
            var b = new Date(d), n = new Date();
            var age = n.getFullYear() - b.getFullYear();
            var m = n.getMonth() - b.getMonth();
            if (m < 0 || (m === 0 && n.getDate() < b.getDate())) age--;
            ageEl.value = age >= 0 && age < 200 ? age + ' years' : '';
        } else { ageEl.value = ''; }
    });
    if (document.getElementById('cp_birthdate').value) {
        var ev = new Event('input');
        document.getElementById('cp_birthdate').dispatchEvent(ev);
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        errBox.style.display = 'none';
        var f = document.getElementById('cp_first').value.trim();
        var l = document.getElementById('cp_last').value.trim();
        var mi = document.getElementById('cp_middle').value.trim();
        var sex = document.getElementById('cp_sex').value;
        var bd = document.getElementById('cp_birthdate').value;
        var em = document.getElementById('cp_email').value.trim();
        var ct = document.getElementById('cp_contact').value.trim();
        var np = document.getElementById('cp_newp').value;
        var cf = document.getElementById('cp_cnfp').value;
        var errs = [];
        if (!nameOk(f)) errs.push('First Name must start with a capital letter, no all-caps, no 3 consecutive letters, no numbers or special characters.');
        if (!nameOk(l)) errs.push('Last Name has the same name rules as First Name.');
        if (mi && !/^[A-Z]$/.test(mi)) errs.push('Middle Initial must be one capital letter only.');
        if (!sex) errs.push('Please select your gender.');
        if (!bd || new Date(bd) >= new Date(new Date().toDateString())) errs.push('Please enter a valid birth date (not in the future).');
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) errs.push('Please enter a valid email address.');
        if (!phOk(ct)) errs.push('Please enter a valid Philippine mobile number (e.g., 0917-123-4567).');
        if (!addrOk(document.getElementById('cp_address').value)) errs.push('Address contains invalid characters (letters, numbers, spaces and ., \\\'#- only).');
        if (np && (np.length < 8 || np.length > 30)) errs.push('New password must be 8-30 characters.');
        if (np && np !== cf) errs.push('Passwords do not match.');
        if (errs.length) {
            errBox.innerHTML = errs.slice(0,3).map(function(m){return '<div style="margin-bottom:0.25rem;"><i class="fas fa-exclamation-triangle"></i> '+m+'</div>';}).join('');
            errBox.style.display = 'block';
            return;
        }
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
        var fd = new FormData(form);
        fetch('<?php echo $cp_ajax; ?>', { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (d.ok) { window.location.reload(); }
                else {
                    errBox.innerHTML = '<i class="fas fa-exclamation-triangle"></i> ' + (d.message || 'Something went wrong. Please try again.');
                    errBox.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="fas fa-check"></i> Save &amp; Continue';
                }
            })
            .catch(function () {
                errBox.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Network error. Please try again.';
                errBox.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fas fa-check"></i> Save &amp; Continue';
            });
    });
    modal.addEventListener('click', function (e) { if (e.target === modal) { /* blocking: keep open */ } });
})();
</script>
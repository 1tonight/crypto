document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const roleSelectionView = document.getElementById('roleSelectionView');
    const adminLoginView = document.getElementById('adminLoginView');
    const adminView = document.getElementById('adminView');
    const parentView = document.getElementById('parentView');
    const allViews = [roleSelectionView, adminLoginView, adminView, parentView];

    const showAdminLoginBtn = document.getElementById('showAdminLoginBtn');
    const showParentViewBtn = document.getElementById('showParentViewBtn');
    const backToRoleBtns = document.querySelectorAll('.back-to-role-btn');

    const adminLoginForm = document.getElementById('adminLoginForm');
    const loginErrorMessage = document.getElementById('loginErrorMessage');
    const adminLogoutBtn = document.getElementById('adminLogoutBtn');

    const createFormAdmin = document.getElementById('createFormAdmin');
    const adminFormsList = document.getElementById('adminFormsList');
    const createFormErrorMessage = document.getElementById('createFormErrorMessage');

    const findFormsParent = document.getElementById('findFormsParent');
    const parentEmailLookupInput = document.getElementById('parentEmailLookup');
    const parentFormsArea = document.getElementById('parentFormsArea');
    const parentFormsList = document.getElementById('parentFormsList');

    const signingModal = document.getElementById('signingModal');
    const closeSigningModal = document.getElementById('closeSigningModal');
    const signingModalTitle = document.getElementById('signingModalTitle');
    const modalFormTitle = document.getElementById('modalFormTitle');
    const modalFormDescription = document.getElementById('modalFormDescription');
    const modalFormStudentName = document.getElementById('modalFormStudentName');
    
    const signatureForm = document.getElementById('signatureForm');
    const signingFormIdInput = document.getElementById('signingFormId');
    const typedSignatureInput = document.getElementById('typedSignature');
    const clearSignatureBtn = document.getElementById('clearSignatureBtn');
    const signatureConsent = document.getElementById('signatureConsent');
    const signingErrorMessage = document.getElementById('signingErrorMessage');
    const submitSignatureBtn = document.getElementById('submitSignatureBtn');

    const messageArea = document.getElementById('messageArea');

    // Signature Pad Setup
    const canvas = document.getElementById('signature-pad');
    console.log(canvas);
    // Adjust canvas size based on its container for responsiveness
    function resizeCanvas() {
        const container = canvas.parentElement;
        console.log('Resizing canvas. Container offsetWidth:', container.offsetWidth, 'offsetHeight:', container.offsetHeight);
        // console.log('Canvas current offsetWidth:', canvas.offsetWidth, 'offsetHeight:', canvas.offsetHeight); // For debugging, can be removed later

        const ratio =  Math.max(window.devicePixelRatio || 1, 1);

        // Use the container's dimensions for setting the canvas drawing buffer size
        canvas.width = container.offsetWidth * ratio;
        canvas.height = container.offsetHeight * ratio;
        
        // Set the CSS style of the canvas to fill the container
        // This ensures the display size matches the drawing buffer size scaled by devicePixelRatio
        canvas.style.width = container.offsetWidth + "px";
        canvas.style.height = container.offsetHeight + "px";

        console.log('Canvas new attribute width:', canvas.width, 'height:', canvas.height);
        console.log('Canvas style width:', canvas.style.width, 'style.height:', canvas.style.height);

        canvas.getContext("2d").scale(ratio, ratio);
        if (signaturePad && typeof signaturePad.clear === 'function') {
            signaturePad.clear(); 
        }
    }
    // Call resizeCanvas initially and on window resize (debounced for performance)
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(resizeCanvas, 250);
    });
    // Initial resize after a short delay for layout to settle
    setTimeout(resizeCanvas, 100); 

    const signaturePad = new SignaturePad(canvas, {
        backgroundColor: 'rgb(255, 255, 255)' // Ensure background is white
    });
    signaturePad.clear(); // Clear any default markings

    // --- Utility Functions ---
    function showView(viewToShow) {
        allViews.forEach(view => view.classList.add('hidden'));
        if (viewToShow) {
            viewToShow.classList.remove('hidden');
        } else {
            roleSelectionView.classList.remove('hidden'); // Default to role selection
        }
        clearMessage(); // Clear general messages when view changes
    }

    function showMessage(text, type = 'info') { // type can be 'success' or 'error'
        messageArea.textContent = text;
        messageArea.className = 'message-area'; // Reset classes
        if (type === 'success') {
            messageArea.classList.add('success');
        } else if (type === 'error') {
            messageArea.classList.add('error');
        }
        messageArea.classList.remove('hidden');
    }

    function clearMessage() {
        messageArea.classList.add('hidden');
        messageArea.textContent = '';
        messageArea.className = 'message-area hidden';
    }

    // --- Login/Session State & Functions ---
    let isAdminLoggedIn = false;

    async function checkLoginStatus() {
        try {
            const response = await fetch('/api/session');
            const data = await response.json();
            isAdminLoggedIn = data.loggedIn;
            updateAdminButtonText();
        } catch (error) {
            console.error('Error checking session:', error);
            isAdminLoggedIn = false;
            updateAdminButtonText();
        }
    }

    function updateAdminButtonText() {
        if (isAdminLoggedIn) {
            showAdminLoginBtn.textContent = 'Access Admin Panel';
        } else {
            showAdminLoginBtn.textContent = 'Admin Login';
        }
    }
    
    adminLoginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginErrorMessage.textContent = '';
        const formData = new FormData(adminLoginForm);
        const data = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (response.ok) {
                adminLoginForm.reset();
                await checkLoginStatus();
                showView(adminView);
                renderAdminForms();
            } else {
                const errorData = await response.json();
                loginErrorMessage.textContent = errorData.error || 'Login failed.';
            }
        } catch (error) {
            loginErrorMessage.textContent = 'An error occurred. Please try again.';
        }
    });

    adminLogoutBtn.addEventListener('click', async () => {
        try {
            const response = await fetch('/api/logout', { method: 'POST' });
            if (response.ok) {
                await checkLoginStatus();
                showView(roleSelectionView);
            } else {
                showMessage('Logout failed.', 'error');
            }
        } catch (error) {
            showMessage('An error occurred during logout.', 'error');
        }
    });

    // --- Event Listeners for Main View Buttons ---
    showAdminLoginBtn.addEventListener('click', () => {
        if (isAdminLoggedIn) {
            showView(adminView);
            renderAdminForms();
        } else {
            loginErrorMessage.textContent = '';
            showView(adminLoginView);
        }
    });

    showParentViewBtn.addEventListener('click', () => {
        showView(parentView);
        parentEmailLookupInput.value = '';
        parentFormsArea.classList.add('hidden');
        parentFormsList.innerHTML = '<p>Enter your email above to find forms.</p>';
    });

    backToRoleBtns.forEach(btn => {
        btn.addEventListener('click', () => showView(roleSelectionView));
    });

    // --- Admin Logic (Form Creation & Listing) ---
    async function renderAdminForms() {
        if (!isAdminLoggedIn) {
            adminFormsList.innerHTML = '<p class="error-message">You must be logged in.</p>';
            showView(adminLoginView);
            return;
        }
        adminFormsList.innerHTML = '<p>Loading forms...</p>';
        try {
            const response = await fetch('/api/forms');
            if (!response.ok) {
                if (response.status === 401) {
                    showMessage('Session expired. Please log in again.', 'error');
                    await checkLoginStatus(); // Update state
                    showView(adminLoginView);
                } else {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return;
            }
            const forms = await response.json();
            if (forms.length === 0) {
                adminFormsList.innerHTML = '<p>No forms created yet.</p>';
            } else {
                adminFormsList.innerHTML = `
                    <table>
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>Student</th>
                                <th>Parent Email</th>
                                <th>Status</th>
                                <th>Digitally Signed</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${forms.map(form => `
                                <tr>
                                    <td>${form.title}</td>
                                    <td>${form.studentName}</td>
                                    <td>${form.parentEmail}</td>
                                    <td>${form.status}</td>
                                    <td>${form.isDigitallySigned ? 'Yes' : 'No'}</td>
                                    <td><button class="secondary-btn view-audit-btn" data-form-id="${form.id}">View Audit</button></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>`;
            }
        } catch (error) {
            adminFormsList.innerHTML = `<p class="error-message">Could not load forms: ${error.message}</p>`;
        }
    }

    createFormAdmin.addEventListener('submit', async (e) => {
        e.preventDefault();
        createFormErrorMessage.textContent = '';
        const formData = new FormData(createFormAdmin);
        const data = Object.fromEntries(formData.entries());
        
        try {
            const response = await fetch('/api/forms', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (!response.ok) {
                const errorData = await response.json();
                if (errorData.errors && Array.isArray(errorData.errors)) {
                    createFormErrorMessage.innerHTML = errorData.errors.map(err => `<span>${err.msg}</span>`).join('<br>');
                } else if (errorData.error) {
                     createFormErrorMessage.textContent = errorData.error;
                } else {
                    createFormErrorMessage.textContent = 'An unknown error occurred.';
                }
                 if (response.status === 401) {
                    showMessage('Session expired. Please log in again.', 'error');
                    await checkLoginStatus();
                    showView(adminLoginView);
                }
                return;
            }
            createFormAdmin.reset();
            showMessage('Form created successfully!', 'success');
            renderAdminForms();
        } catch (error) {
            createFormErrorMessage.textContent = "A network error occurred. Please try again.";
        }
    });

    // Event delegation for "View Audit" buttons
    adminFormsList.addEventListener('click', async (e) => {
        if (e.target.classList.contains('view-audit-btn')) {
            const formId = e.target.dataset.formId;
             if (!isAdminLoggedIn) { 
                showMessage('Please log in to view audit trails.', 'error');
                return;
            }
            try {
                // In a real app, you might fetch just one form's audit trail.
                // For now, we refetch all and find.
                const response = await fetch('/api/forms');
                if(!response.ok) throw new Error("Failed to fetch forms for audit trail");
                
                const forms = await response.json();
                const form = forms.find(f => f.id === formId);

                if(form && form.auditTrail) {
                    const trail = JSON.parse(form.auditTrail); // Assuming auditTrail is stored as JSON string
                    let trailString = `Audit Trail for: ${form.title}\n\n`;
                    trail.forEach(entry => {
                        trailString += `Event: ${entry.event}\nTimestamp: ${new Date(entry.timestamp).toLocaleString()}\nIP: ${entry.ip || 'N/A'}\nAdmin: ${entry.admin || 'N/A'}\nHash Signed: ${entry.hash_signed || ''}\nError: ${entry.error || ''}\n\n`;
                    });
                    if(form.documentHash) {
                         trailString += `DOCUMENT HASH (at signing):\n${form.documentHash}\n\n`;
                    }
                    if(form.isDigitallySigned) {
                        trailString += `DIGITAL SIGNATURE STATUS: Signed`;
                    }
                    alert(trailString); // Simple alert, could be a modal
                } else {
                    showMessage("Audit trail not found or inaccessible.", "error");
                }
            } catch (error) {
                showMessage(`Could not retrieve audit trail: ${error.message}`, "error");
            }
        }
    });

    // --- Parent Logic (Form Listing & Signing) ---
    findFormsParent.addEventListener('submit', async (e) => {
        e.preventDefault();
        parentFormsList.innerHTML = '<p>Loading forms...</p>';
        parentFormsArea.classList.remove('hidden');
        const email = parentEmailLookupInput.value;
        if (!email) {
            parentFormsList.innerHTML = '<p class="error-message">Please enter an email address.</p>';
            return;
        }
        try {
            const response = await fetch(`/api/forms/parent/${encodeURIComponent(email)}`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const forms = await response.json();
            
            if (forms.length === 0) {
                parentFormsList.innerHTML = '<p>No forms found for this email, or all forms are signed.</p>';
            } else {
                parentFormsList.innerHTML = forms.map(form => `
                    <div class="card form-item" data-form-id="${form.id}" data-title="${form.title}" data-description="${form.description}" data-student="${form.studentName}">
                        <h4>${form.title} for ${form.studentName}</h4>
                        <p>Status: ${form.status}</p>
                        <p>Description: ${form.description || 'No description.'}</p>
                        ${form.status === 'Pending' ? `<button class="view-sign-btn primary-btn">View & Sign</button>` : `<p>Completed.</p>`}
                    </div>
                `).join('');
            }
        } catch (error) {
            parentFormsList.innerHTML = `<p class="error-message">Could not retrieve forms: ${error.message}</p>`;
        }
    });

    // Event delegation for "View & Sign" buttons
    parentFormsList.addEventListener('click', (e) => {
        if (e.target.classList.contains('view-sign-btn')) {
            const formItem = e.target.closest('.form-item');
            const formId = formItem.dataset.formId;
            const title = formItem.dataset.title;
            const description = formItem.dataset.description;
            const studentName = formItem.dataset.student;
            openSigningModal(formId, title, description, studentName);
        }
    });
    
    function openSigningModal(formId, title, description, studentName) {
        signingFormIdInput.value = formId;
        modalFormTitle.textContent = title || 'N/A';
        modalFormDescription.textContent = description || 'N/A';
        modalFormStudentName.textContent = studentName || 'N/A';
        
        signaturePad.clear();
        typedSignatureInput.value = '';
        signatureConsent.checked = false;
        signingErrorMessage.textContent = '';
        signingModal.style.display = 'flex'; // Use flex for centering defined in modal CSS
        resizeCanvas(); // Ensure canvas is sized correctly when modal opens
    }

    closeSigningModal.addEventListener('click', () => signingModal.style.display = 'none');
    clearSignatureBtn.addEventListener('click', () => signaturePad.clear());

    signatureForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        signingErrorMessage.textContent = '';

        if (!signatureConsent.checked) {
            signingErrorMessage.textContent = "You must consent to sign electronically.";
            return;
        }
        if (signaturePad.isEmpty()) {
            signingErrorMessage.textContent = "Please provide a drawn signature.";
            return;
        }
        if (!typedSignatureInput.value.trim()) {
            signingErrorMessage.textContent = "Please type your full name.";
            return;
        }

        submitSignatureBtn.disabled = true;
        submitSignatureBtn.textContent = "Submitting...";

        const formId = signingFormIdInput.value;
        const data = {
            typedSignature: typedSignatureInput.value.trim(),
            signatureDataUrl: signaturePad.toDataURL() 
        };

        try {
            const response = await fetch(`/api/forms/${formId}/sign`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            
            const responseData = await response.json();

            if (response.ok) {
                showMessage('Form signed successfully with a digital signature!', 'success');
                signingModal.style.display = 'none';
                // Trigger a refresh of the parent's form list
                if (parentEmailLookupInput.value) {
                     findFormsParent.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
                }
            } else {
                signingErrorMessage.textContent = responseData.error || 'Could not sign form. Please try again.';
            }
        } catch (error) {
            signingErrorMessage.textContent = "A network error occurred. Please try again.";
        } finally {
            submitSignatureBtn.disabled = false;
            submitSignatureBtn.textContent = "Submit Digital Signature";
        }
    });

    // --- Initial Setup ---
    checkLoginStatus().then(() => {
        showView(roleSelectionView); 
    });

    // Close modal if clicked outside of its content area
    window.addEventListener('click', (event) => {
        if (event.target == signingModal) {
            signingModal.style.display = "none";
        }
    });
});
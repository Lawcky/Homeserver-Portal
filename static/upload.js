document.addEventListener("DOMContentLoaded", () => {
    const uploadForm = document.getElementById("uploadForm");
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-upload");
    const fileList = document.getElementById("fileList");
    const uploadBtn = document.getElementById("uploadBtn");
    const adminBtn = document.getElementById("admin");

    let filesToUpload = [];

    function renderFileList() {
        fileList.innerHTML = "";
        if (filesToUpload.length === 0) return;

        filesToUpload.forEach((file, idx) => {
            const div = document.createElement("div");
            div.classList.add("file-item");
            div.textContent = `${file.name} (${Math.round(file.size / 1024)} KB)`;
            
            const removeBtn = document.createElement("button");
            removeBtn.textContent = "x";
            removeBtn.type = "button";
            removeBtn.classList.add("remove-btn");
            removeBtn.addEventListener("click", () => {
                filesToUpload.splice(idx, 1);
                renderFileList();
            });

            div.appendChild(removeBtn);
            fileList.appendChild(div);
        });
    }

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");

        const newFiles = Array.from(e.dataTransfer.files);
        filesToUpload = filesToUpload.concat(newFiles);
        renderFileList();
    });

    dropzone.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", (e) => {
        const newFiles = Array.from(e.target.files);
        filesToUpload = filesToUpload.concat(newFiles);
        renderFileList();
    });

    uploadBtn.addEventListener("click", async () => {
        if (filesToUpload.length === 0) {
            alert("No files selected!");
            return;
        }

        uploadBtn.disabled = true //avoid multiple clicks

        const formData = new FormData(uploadForm);
        
        try {
            // add files to be uploaded
            if (adminBtn.disabled === true) {
                // first check if the size is above what's allowed (10MB)
                filesToUpload.forEach(file => {
                    if (file.size <= 10 * 1024 * 1024) { 
                        formData.append("files", file);
                    } else {
                        throw new Error("Size too large, get admin account or upload lighter files (10MB max)");
                    }
                });
            } else {
                filesToUpload.forEach(file => formData.append("files", file));
            }
        } catch (error) {
            alert(error.message); //gives error
            filesToUpload = []; //reset files to upload
            renderFileList(); // render the removal of to be uploaded files
            uploadBtn.disabled = false; // make upload available again
            return;
        }

        try {
            const res = await fetch(uploadForm.action, {
                method: "POST",
                body: formData,
            });

            if (!res.ok) throw new Error(`Server error: ${res.status} - Server Response : ${await res.text()}`);

            const result = await res.text();
            alert("Upload successful!\n" + result);
            uploadBtn.disabled = false //make upload available again
            filesToUpload = [];
            renderFileList();
        } catch (err) {
            alert("Upload failed: " + err.message);
            uploadBtn.disabled = false //make upload available again
        }
    });
});

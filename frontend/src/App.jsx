import { useState, useEffect } from "react";
import { FaEye, FaEyeSlash } from "react-icons/fa";
import { FaCheckCircle, FaTimesCircle } from "react-icons/fa";
import { AiOutlineClose } from "react-icons/ai";
import "./App.css";

function extractDecision(result) {
  if (result.decision && result.decision !== "-") {
    if (result.decision.includes("Shortlist"))
      return (
        <span>
          <FaCheckCircle style={{ color: "green", marginRight: 4 }} />{" "}
          Shortlisted
        </span>
      );
    if (result.decision.includes("Reject"))
      return (
        <span>
          <FaTimesCircle style={{ color: "red", marginRight: 4 }} /> Rejected
        </span>
      );
    return result.decision;
  }
  if (result.result_text) {
    const match = result.result_text.match(/Decision:\s*(Shortlist|Reject)/);
    if (match) {
      return match[1] === "Shortlist" ? (
        <span>
          <FaCheckCircle style={{ color: "green", marginRight: 4 }} />{" "}
          Shortlisted
        </span>
      ) : (
        <span>
          <FaTimesCircle style={{ color: "red", marginRight: 4 }} /> Rejected
        </span>
      );
    }
  }
  if (result.error) return "Error";
  return "-";
}

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

// Resume Screening Component
function ResumeScreening({ token }) {
  const [jd, setJd] = useState("");
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState([]);
  const [hiringType, setHiringType] = useState("1");
  const [level, setLevel] = useState("1");
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    setFiles(Array.from(e.target.files));
  };

  const removeFile = (index) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!jd.trim()) {
      alert("Please enter a job description");
      return;
    }
    if (files.length === 0) {
      alert("Please select at least one resume file");
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append("job_description", jd);
    formData.append("hiring_type", hiringType);
    formData.append("level", level);
    files.forEach((file) => {
      formData.append("files", file);
    });

    try {
      const response = await fetch(`${API_URL}/analyze-resumes/`, {
        method: "POST",
        body: formData,
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Analysis failed");
      }
      setResults(data.results || []);
      setFiles([]);
    } catch (err) {
      setResults([]);
      alert(`Error: ${err.message}`);
    }
    setLoading(false);
  };

  return (
    <div className="page-content">
      <h2 className="page-title">Resume Screening</h2>
      <div className="columns">
        <div className="left-column">
          <h3>Job Description</h3>
          <div style={{ marginBottom: "1rem" }} className="field-row">
            <label>
              Hiring Type:
              <select
                value={hiringType}
                onChange={(e) => setHiringType(e.target.value)}
              >
                <option value="1">Sales</option>
                <option value="2">IT</option>
                <option value="3">Non-Sales</option>
                <option value="4">Sales Support</option>
              </select>
            </label>
            <label>
              Level:
              <select value={level} onChange={(e) => setLevel(e.target.value)}>
                <option value="1">Fresher</option>
                <option value="2">Experienced</option>
              </select>
            </label>
          </div>
          <textarea
            value={jd}
            onChange={(e) => setJd(e.target.value)}
            placeholder="Paste Job Description here..."
            rows={20}
            style={{ width: "100%" }}
          />
        </div>
        <div className="right-column">
          <h3>Upload Resumes</h3>
          <div className="upload-row">
            <label className="custom-file-upload">
              <input
                type="file"
                accept=".pdf,.doc,.docx,.png,.jpg,.jpeg,.gif,.bmp,.tiff,.webp"
                multiple
                onChange={handleFileChange}
                style={{ display: "none" }}
              />
              Choose Files
            </label>
            <button onClick={handleSubmit} disabled={loading}>
              {loading ? "Evaluating..." : "Evaluate"}
            </button>
          </div>
          {files.length > 0 && (
            <div className="file-list">
              {files.map((file, idx) => (
                <span className="file-item" key={idx}>
                  {file.name}
                  <button
                    type="button"
                    className="remove-file"
                    onClick={() => removeFile(idx)}
                    title="Remove"
                  >
                    <AiOutlineClose size={16} />
                  </button>
                </span>
              ))}
            </div>
          )}
          <div style={{ marginTop: "2rem" }}>
            {results.length > 0 && (
              <table>
                <thead>
                  <tr>
                    <th>Resume</th>
                    <th>Match %</th>
                    <th>Decision</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((res, idx) => (
                    <tr key={idx}>
                      <td data-label="Resume">{res.filename}</td>
                      <td data-label="Match %">
                        {res.match_percent !== undefined
                          ? res.match_percent + "%"
                          : "-"}
                      </td>
                      <td data-label="Decision">{extractDecision(res)}</td>
                      <td data-label="Details">
                        <details>
                          <summary>Show</summary>
                          <pre style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                            {(res.result_text || res.error)?.replace(
                              /\*\*(.*?)\*\*/g,
                              "$1"
                            )}
                          </pre>
                        </details>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// MIS Summary Component
function MISSummary({ setViewingFile, setViewingFilename }) {
  const [mis, setMis] = useState([]);
  const [misLoading, setMisLoading] = useState(false);

  const fetchMIS = async () => {
    setMisLoading(true);
    try {
      const response = await fetch(`${API_URL}/mis-summary`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to fetch MIS summary");
      }
      setMis(data.summary || []);
    } catch (err) {
      setMis([]);
      alert(`Error: ${err.message}`);
    }
    setMisLoading(false);
  };

  const hiringTypeLabel = (val) => {
    if (!val) return "-";
    if (val === "1" || val === 1) return "Sales";
    if (val === "2" || val === 2) return "IT";
    if (val === "3" || val === 3) return "Non-Sales";
    if (val === "4" || val === 4) return "Sales Support";
    return val;
  };

  const levelLabel = (val) => {
    if (!val) return "-";
    if (val === "1" || val === 1) return "Fresher";
    if (val === "2" || val === 2) return "Experienced";
    return val;
  };

  return (
    <div className="page-content">
      <div className="mis-summary-section">
        <h2 className="page-title">MIS Summary</h2>
        <button
          onClick={fetchMIS}
          disabled={misLoading}
          style={{ marginBottom: "1rem" }}
        >
          {misLoading ? "Loading..." : "Show MIS Summary"}
        </button>
        {mis.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Recruiter Name</th>
                <th>Uploads</th>
                <th>Total Resumes</th>
                <th>Shortlisted</th>
                <th>Rejected</th>
                <th>History</th>
              </tr>
            </thead>
            <tbody>
              {mis.map((row, idx) => (
                <tr key={idx}>
                  <td data-label="Recruiter Name">{row.recruiter_name}</td>
                  <td data-label="Uploads">{row.uploads}</td>
                  <td data-label="Total Resumes">{row.resumes}</td>
                  <td data-label="Shortlisted">{row.shortlisted}</td>
                  <td data-label="Rejected">{row.rejected}</td>
                  <td data-label="History">
                    {row.history && row.history.length > 0 ? (
                      <details>
                        <summary>Show</summary>
                        <table style={{ fontSize: 12, marginTop: 8 }}>
                          <thead>
                            <tr>
                              <th>Resume Name</th>
                              <th>Hiring Type</th>
                              <th>Level</th>
                              <th>Match %</th>
                              <th>Decision</th>
                              <th>Upload Date</th>
                              <th>Counts/Day</th>
                              <th>Details</th>
                            </tr>
                          </thead>
                          <tbody>
                            {row.history.map((h, hidx) => (
                              <tr key={hidx}>
                                <td data-label="Resume Name">
                                  {h.file_id ? (
                                    <a
                                      href="#"
                                      onClick={(e) => {
                                        e.preventDefault();
                                        setViewingFile(h.file_id);
                                        setViewingFilename(
                                          h.resume_name || "Unknown"
                                        );
                                      }}
                                      style={{
                                        color: "#2563eb",
                                        textDecoration: "none",
                                        cursor: "pointer",
                                      }}
                                    >
                                      {h.resume_name || "Unknown"}
                                    </a>
                                  ) : (
                                    h.resume_name || "Unknown"
                                  )}
                                </td>
                                <td data-label="Hiring Type">
                                  {hiringTypeLabel(h.hiring_type)}
                                </td>
                                <td data-label="Level">
                                  {levelLabel(h.level)}
                                </td>
                                <td data-label="Match %">
                                  {h.match_percent !== undefined &&
                                  h.match_percent !== null
                                    ? h.match_percent + "%"
                                    : "-"}
                                </td>
                                <td data-label="Decision">
                                  {h.decision || "-"}
                                </td>
                                <td data-label="Upload Date">
                                  {h.upload_date || "-"}
                                </td>
                                <td data-label="Counts/Day">
                                  {h.counts_per_day || "-"}
                                </td>
                                <td data-label="Details">
                                  <details>
                                    <summary>Show</summary>
                                    <pre
                                      style={{
                                        whiteSpace: "pre-wrap",
                                        fontSize: 11,
                                      }}
                                    >
                                      {(h.details || "").replace(
                                        /\*\*(.*?)\*\*/g,
                                        "$1"
                                      )}
                                    </pre>
                                  </details>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </details>
                    ) : (
                      "No history"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// Resume Viewer Component
function ResumeViewer({ fileId, filename, onClose, token }) {
  const [fileData, setFileData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchFile = async () => {
      try {
        const response = await fetch(`${API_URL}/view-resume/${fileId}`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.detail || "Failed to load file");
        }
        setFileData(data);
      } catch (err) {
        setError(err.message);
      }
      setLoading(false);
    };

    if (fileId) {
      fetchFile();
    }
  }, [fileId, token]);

  const handleDownload = async () => {
    try {
      const response = await fetch(`${API_URL}/download-resume/${fileId}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (!response.ok) {
        throw new Error("Download failed");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Download failed: ${err.message}`);
    }
  };

  if (loading) {
    return (
      <div
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: "rgba(0,0,0,0.8)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 1000,
        }}
      >
        <div style={{ color: "white", fontSize: "1.2rem" }}>Loading...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: "rgba(0,0,0,0.8)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 1000,
        }}
      >
        <div
          style={{
            backgroundColor: "white",
            padding: "2rem",
            borderRadius: "8px",
            textAlign: "center",
          }}
        >
          <div style={{ color: "red", marginBottom: "1rem" }}>{error}</div>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "rgba(0,0,0,0.9)",
        zIndex: 1000,
      }}
    >
      <div
        style={{
          position: "absolute",
          top: "10px",
          left: "50%",
          transform: "translateX(-50%)",
          display: "flex",
          gap: "1rem",
        }}
      >
        <button
          onClick={handleDownload}
          style={{
            background: "#2563eb",
            color: "white",
            border: "none",
            padding: "0.5rem 1rem",
            borderRadius: "4px",
            cursor: "pointer",
          }}
        >
          Download
        </button>
        <button
          onClick={onClose}
          style={{
            background: "#ef4444",
            color: "white",
            border: "none",
            padding: "0.5rem 1rem",
            borderRadius: "4px",
            cursor: "pointer",
          }}
        >
          Close
        </button>
      </div>

      <div
        style={{ padding: "60px 20px 20px", height: "100vh", overflow: "auto" }}
      >
        {fileData && (
          <div
            style={{
              backgroundColor: "white",
              margin: "0 auto",
              maxWidth: "900px",
              minHeight: "calc(100vh - 80px)",
            }}
          >
            {fileData.content_type?.includes("pdf") ? (
              <iframe
                src={`data:application/pdf;base64,${fileData.content}`}
                style={{
                  width: "100%",
                  height: "calc(100vh - 80px)",
                  border: "none",
                }}
                title={filename}
              />
            ) : fileData.content_type?.includes("image") ? (
              <img
                src={`data:${fileData.content_type};base64,${fileData.content}`}
                alt={filename}
                style={{ width: "100%", height: "auto" }}
              />
            ) : (
              <div style={{ padding: "2rem", textAlign: "center" }}>
                <h3>{filename}</h3>
                <p>File type: {fileData.content_type}</p>
                <p>Size: {(fileData.size / 1024).toFixed(2)} KB</p>
                <p>
                  Preview not available for this file type. Use the download
                  button to view the file.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}



// Daily Reports Component (Modern Design)
function DailyReports() {
  const [reportData, setReportData] = useState(null);
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [loading, setLoading] = useState(false);

  const fetchReportsForDate = async (date) => {
    setLoading(true);
    setSelectedDate(date);

    // Format date as YYYY-MM-DD
    const formattedDate = date.toISOString().split("T")[0];

    try {
      const response = await fetch(`${API_URL}/reports/${formattedDate}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Failed to fetch reports");
      setReportData(data);
    } catch (err) {
      setReportData(null);
      alert(`Error: ${err.message}`);
    }

    setLoading(false);
  };

  const downloadReport = () => {
    if (!reportData) return;

    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += `Daily Report - ${reportData.date}\n\n`;
    csvContent += "Recruiter Name,Total Resumes,Shortlisted,Rejected\n";

    reportData.reports.forEach((row) => {
      csvContent += `${row.recruiter_name},${row.total_resumes},${row.shortlisted},${row.rejected}\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute(
      "download",
      `daily_report_${selectedDate.toISOString().split("T")[0]}.csv`
    );
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Automatically fetch today's report on mount
  useEffect(() => {
    fetchReportsForDate(selectedDate);
  }, []);

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>Daily Reports</h2>

      {/* Date Selector */}
      <div style={styles.dateSelector}>
        <label style={{ marginRight: "10px", fontWeight: 500 }}>Select Date:</label>
        <input
          type="date"
          value={selectedDate.toISOString().split("T")[0]}
          onChange={(e) => {
            const pickedDate = new Date(e.target.value);
            fetchReportsForDate(pickedDate);
          }}
          style={styles.dateInput}
        />
        <button style={styles.downloadBtn} onClick={downloadReport} disabled={!reportData}>
          Download CSV
        </button>
      </div>

      {/* Report Cards */}
      {loading ? (
        <p style={{ textAlign: "center", marginTop: "3rem", color: "#666" }}>Loading report...</p>
      ) : reportData && reportData.reports.length > 0 ? (
        <div style={styles.cardsContainer}>
          {reportData.reports.map((row, idx) => (
            <div key={idx} style={styles.card}>
              <h3 style={styles.cardTitle}>{row.recruiter_name}</h3>
              <div style={styles.cardContent}>
                <div style={styles.stat}>
                  <span style={styles.statNumber}>{row.total_resumes}</span>
                  <span style={styles.statLabel}>Total Resumes</span>
                </div>
                <div style={styles.stat}>
                  <span style={{ ...styles.statNumber, color: "#4caf50" }}>{row.shortlisted}</span>
                  <span style={styles.statLabel}>Shortlisted</span>
                </div>
                <div style={styles.stat}>
                  <span style={{ ...styles.statNumber, color: "#f44336" }}>{row.rejected}</span>
                  <span style={styles.statLabel}>Rejected</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p style={{ textAlign: "center", marginTop: "3rem", color: "#666" }}>
          No data available for {selectedDate.toLocaleDateString()}
        </p>
      )}
    </div>
  );
}

// Styles
const styles = {
  container: {
    maxWidth: "900px",
    margin: "2rem auto",
    padding: "0 1rem",
    fontFamily: "Arial, sans-serif",
  },
  title: {
    textAlign: "center",
    marginBottom: "2rem",
    color: "#232946",
    fontSize: "2rem",
  },
  dateSelector: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    gap: "1rem",
    marginBottom: "2rem",
    flexWrap: "wrap",
  },
  dateInput: {
    padding: "8px 12px",
    borderRadius: "6px",
    border: "1px solid #ccc",
    fontSize: "1rem",
  },
  downloadBtn: {
    padding: "8px 16px",
    backgroundColor: "#4F75FF",
    color: "#fff",
    border: "none",
    borderRadius: "6px",
    cursor: "pointer",
    fontWeight: "600",
    transition: "all 0.2s",
  },
  cardsContainer: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
    gap: "1.5rem",
  },
  card: {
    backgroundColor: "#fff",
    borderRadius: "12px",
    boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
    padding: "1.5rem",
    transition: "transform 0.2s, box-shadow 0.2s",
    cursor: "pointer",
  },
  cardTitle: {
    fontSize: "1.2rem",
    marginBottom: "1rem",
    color: "#232946",
    textAlign: "center",
  },
  cardContent: {
    display: "flex",
    justifyContent: "space-around",
  },
  stat: {
    textAlign: "center",
  },
  statNumber: {
    fontSize: "1.5rem",
    fontWeight: "700",
    display: "block",
  },
  statLabel: {
    fontSize: "0.85rem",
    color: "#666",
  },
};


// Dashboard Component (Navigation)
function Dashboard({
  currentPage,
  setCurrentPage,
  recruiterName,
  handleLogout,
}) {
  return (
    <div className="dashboard-header">
      <div className="navigation-bar">
        <div className="nav-links">
          <button
            className={`nav-link ${
              currentPage === "resume-screening" ? "active" : ""
            }`}
            onClick={() => setCurrentPage("resume-screening")}
          >
            Resume Screening
          </button>
          <button
            className={`nav-link ${
              currentPage === "mis-summary" ? "active" : ""
            }`}
            onClick={() => setCurrentPage("mis-summary")}
          >
            MIS Summary
          </button>
          <button
            className={`nav-link ${
              currentPage === "daily-reports" ? "active" : ""
            }`}
            onClick={() => setCurrentPage("daily-reports")}
          >
            Daily Reports
          </button>
        </div>
        <div className="user-info">
          <span>
            Logged in as <b>{recruiterName}</b>
          </span>
          <button onClick={handleLogout} className="logout-btn">
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}

function App() {
  // Auth state
  const [authMode, setAuthMode] = useState("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [recruiterName, setRecruiterName] = useState(
    localStorage.getItem("recruiterName") || ""
  );
  const [authError, setAuthError] = useState("");
  const [authSuccess, setAuthSuccess] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  // Navigation state
  const [currentPage, setCurrentPage] = useState("resume-screening");

  // Password visibility state
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [showRegisterPassword, setShowRegisterPassword] = useState(false);
  const [showResetPassword, setShowResetPassword] = useState(false);

  // Add these states in the App function
  const [viewingFile, setViewingFile] = useState(null);
  const [viewingFilename, setViewingFilename] = useState("");

  // Check for reset token in URL on component mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get("token");
    if (tokenFromUrl) {
      setResetToken(tokenFromUrl);
      setAuthMode("reset-password");
      verifyResetToken(tokenFromUrl);
    }
  }, []);

  // Verify reset token
  const verifyResetToken = async (token) => {
    try {
      const res = await fetch(`${API_URL}/verify-reset-token/${token}`);
      const data = await res.json();
      if (!res.ok) {
        setAuthError(
          "Invalid or expired reset link. Please request a new one."
        );
        setAuthMode("forgot-password");
      } else {
        setEmail(data.email);
        setAuthSuccess("Reset link verified. Please enter your new password.");
      }
    } catch (err) {
      setAuthError("Invalid or expired reset link. Please request a new one.");
      setAuthMode("forgot-password");
    }
  };

  // Auth handlers
  const handleAuth = async (e) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    setAuthSuccess("");

    try {
      if (authMode === "login") {
        const form = new FormData();
        form.append("username", username);
        form.append("password", password);
        const res = await fetch(`${API_URL}/login`, {
          method: "POST",
          body: form,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Login failed");

        setToken(data.access_token);
        setRecruiterName(data.recruiter_name);
        localStorage.setItem("token", data.access_token);
        localStorage.setItem("recruiterName", data.recruiter_name);
      } else if (authMode === "register") {
        const res = await fetch(`${API_URL}/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: username,
            email: email,
            password: password,
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Registration failed");

        setAuthMode("login");
        setAuthSuccess(
          "Registration successful! Please login with your credentials."
        );
        setUsername("");
        setEmail("");
        setPassword("");
      } else if (authMode === "forgot-password") {
        const res = await fetch(`${API_URL}/forgot-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email: email,
          }),
        });
        const data = await res.json();
        if (!res.ok)
          throw new Error(data.detail || "Failed to send reset email");

        setAuthSuccess(
          "If the email exists in our system, you will receive a password reset link shortly. Please check your inbox and spam folder."
        );
        setEmail("");
      } else if (authMode === "reset-password") {
        if (newPassword !== confirmPassword) {
          throw new Error("Passwords do not match");
        }
        if (newPassword.length < 6) {
          throw new Error("Password must be at least 6 characters long");
        }

        const res = await fetch(`${API_URL}/reset-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            token: resetToken,
            new_password: newPassword,
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Failed to reset password");

        setAuthSuccess(
          "Password reset successful! You can now login with your new password."
        );
        setAuthMode("login");
        setNewPassword("");
        setConfirmPassword("");
        setResetToken("");
        window.history.replaceState(
          {},
          document.title,
          window.location.pathname
        );
      }
    } catch (err) {
      setAuthError(err.message);
    }
    setAuthLoading(false);
  };

  const handleLogout = () => {
    setToken("");
    setRecruiterName("");
    localStorage.removeItem("token");
    localStorage.removeItem("recruiterName");
    setCurrentPage("resume-screening");
  };

  const resetAuthState = () => {
    setAuthError("");
    setAuthSuccess("");
    setUsername("");
    setEmail("");
    setPassword("");
    setNewPassword("");
    setConfirmPassword("");
  };

  const renderAuthForm = () => {
    switch (authMode) {
      case "login":
        return (
          <>
            <h2>Recruiter Login</h2>
            <form
              onSubmit={handleAuth}
              style={{
                marginBottom: 16,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Recruiter Username"
                required
              />
              <div className="password-wrapper">
                <input
                  type={showLoginPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  required
                />
                <span
                  className="password-toggle"
                  onClick={() => setShowLoginPassword((prev) => !prev)}
                  title={showLoginPassword ? "Hide Password" : "Show Password"}
                >
                  {showLoginPassword ? <FaEyeSlash /> : <FaEye />}
                </span>
              </div>
              <button type="submit" disabled={authLoading}>
                {authLoading ? "Logging in..." : "Login"}
              </button>
            </form>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <button
                onClick={() => {
                  setAuthMode("register");
                  resetAuthState();
                }}
                style={{ fontSize: 12 }}
              >
                Need an account? Register
              </button>
              <button
                onClick={() => {
                  setAuthMode("forgot-password");
                  resetAuthState();
                }}
                style={{
                  fontSize: 12,
                  color: "#007bff",
                  background: "none",
                  border: "none",
                  textDecoration: "underline",
                  cursor: "pointer",
                }}
              >
                Forgot Password?
              </button>
            </div>
          </>
        );

      case "register":
        return (
          <>
            <h2>Recruiter Registration</h2>
            <form
              onSubmit={handleAuth}
              style={{
                marginBottom: 16,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Recruiter Username"
                required
              />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email Address"
                required
              />
              <div className="password-wrapper">
                <input
                  type={showRegisterPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  required
                  minLength={6}
                />
                <span
                  className="password-toggle"
                  onClick={() => setShowRegisterPassword((prev) => !prev)}
                  title={
                    showRegisterPassword ? "Hide Password" : "Show Password"
                  }
                >
                  {showRegisterPassword ? <FaEyeSlash /> : <FaEye />}
                </span>
              </div>
              <button type="submit" disabled={authLoading}>
                {authLoading ? "Registering..." : "Register"}
              </button>
            </form>
            <button
              onClick={() => {
                setAuthMode("login");
                resetAuthState();
              }}
              style={{ fontSize: 12 }}
            >
              Already have an account? Login
            </button>
          </>
        );

      case "forgot-password":
        return (
          <>
            <h2>Forgot Password</h2>
            <p style={{ fontSize: 14, color: "#666", marginBottom: 16 }}>
              Enter your email address and we'll send you a link to reset your
              password.
            </p>
            <form
              onSubmit={handleAuth}
              style={{
                marginBottom: 16,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email Address"
                required
              />
              <button type="submit" disabled={authLoading}>
                {authLoading ? "Sending..." : "Send Reset Link"}
              </button>
            </form>
            <button
              onClick={() => {
                setAuthMode("login");
                resetAuthState();
              }}
              style={{ fontSize: 12 }}
            >
              Back to Login
            </button>
          </>
        );

      case "reset-password":
        return (
          <>
            <h2>Reset Password</h2>
            <p style={{ fontSize: 14, color: "#666", marginBottom: 16 }}>
              Enter your new password for: <strong>{email}</strong>
            </p>
            <form
              onSubmit={handleAuth}
              style={{
                marginBottom: 16,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              <div className="password-wrapper">
                <input
                  type={showResetPassword ? "text" : "password"}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="New Password"
                  required
                  minLength={6}
                />
                <span
                  className="password-toggle"
                  onClick={() => setShowResetPassword((prev) => !prev)}
                  title={showResetPassword ? "Hide Password" : "Show Password"}
                >
                  {showResetPassword ? <FaEyeSlash /> : <FaEye />}
                </span>
              </div>
              <div className="password-wrapper">
                <input
                  type={showResetPassword ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm New Password"
                  required
                  minLength={6}
                />
                <span
                  className="password-toggle"
                  onClick={() => setShowResetPassword((prev) => !prev)}
                  title={showResetPassword ? "Hide Password" : "Show Password"}
                >
                  {showResetPassword ? <FaEyeSlash /> : <FaEye />}
                </span>
              </div>
              <button type="submit" disabled={authLoading}>
                {authLoading ? "Resetting..." : "Reset Password"}
              </button>
            </form>
            <button
              onClick={() => {
                setAuthMode("login");
                resetAuthState();
                setResetToken("");
                window.history.replaceState(
                  {},
                  document.title,
                  window.location.pathname
                );
              }}
              style={{ fontSize: 12 }}
            >
              Back to Login
            </button>
          </>
        );

      default:
        return null;
    }
  };

  const renderCurrentPage = () => {
    switch (currentPage) {
      case "resume-screening":
        return <ResumeScreening token={token} />;
      case "mis-summary":
        return (
          <MISSummary
            setViewingFile={setViewingFile}
            setViewingFilename={setViewingFilename}
          />
        );
      case "daily-reports":
        return <DailyReports />;
      default:
        return <ResumeScreening token={token} />;
    }
  };

  return (
    <>
      {!token ? (
        <div className="login-container">
          <h1>ProHire</h1>
          <p className="tagline">
            Apply karo chahe kahin se, shortlisting hoga yahin se.
          </p>
          <div className="auth-box">
            {renderAuthForm()}
            {authError && (
              <div
                style={{
                  color: "red",
                  marginTop: 16,
                  padding: 12,
                  backgroundColor: "#ffeaea",
                  border: "1px solid #ffcdd2",
                  borderRadius: 4,
                }}
              >
                {authError}
              </div>
            )}
            {authSuccess && (
              <div
                style={{
                  color: "green",
                  marginTop: 16,
                  padding: 12,
                  backgroundColor: "#eafaf1",
                  border: "1px solid #c8e6c9",
                  borderRadius: 4,
                }}
              >
                {authSuccess}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="main-container">
          <h1>ProHire</h1>
          <p className="tagline">
            Apply karo chahe kahin se, shortlisting hoga yahin se.
          </p>
          <Dashboard
            currentPage={currentPage}
            setCurrentPage={setCurrentPage}
            recruiterName={recruiterName}
            handleLogout={handleLogout}
          />
          {renderCurrentPage()}
        </div>
      )}
      {/* ADD THIS PART - Resume Viewer Modal */}
      {viewingFile && (
        <ResumeViewer
          fileId={viewingFile}
          filename={viewingFilename}
          onClose={() => {
            setViewingFile(null);
            setViewingFilename("");
          }}
          token={token}
        />
      )}
    </>
  );
}

export default App;

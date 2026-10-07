import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import multer from "multer";
import dotenv from "dotenv";
import pg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { spawn } from "child_process";

dotenv.config();

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 10000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_SSL === "true"
      ? { rejectUnauthorized: false }
      : false
});

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";

app.use(
  cors({
    origin: FRONTEND_ORIGIN === "*" ? true : FRONTEND_ORIGIN,
    credentials: true
  })
);

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("combined"));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: Number(
      process.env.MAX_UPLOAD_BYTES || 21474836480
    )
  }
});

const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

const MIN_RUNTIME_MINUTES = Number(
  process.env.MIN_RUNTIME_MINUTES || 90
);

const RUNTIME_TOLERANCE_MINUTES = Number(
  process.env.RUNTIME_TOLERANCE_MINUTES || 3
);

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const token = header.substring(7);

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function requireAdmin(req, res, next) {
  if (
    !req.user ||
    !["admin", "super_admin"].includes(req.user.role)
  ) {
    return res.status(403).json({
      error: "Admin permission required"
    });
  }

  next();
}

function requireSuperAdmin(req, res, next) {
  if (req.user?.role !== "super_admin") {
    return res.status(403).json({
      error: "Super Admin permission required"
    });
  }

  next();
}

async function query(text, params = []) {
  return pool.query(text, params);
}

async function getTmdbMovie(tmdbId) {
  const key = process.env.TMDB_API_KEY;

  if (!key) {
    throw new Error("TMDB_API_KEY is not configured");
  }

  const movieUrl =
    `https://api.themoviedb.org/3/movie/${encodeURIComponent(
      tmdbId
    )}?api_key=${encodeURIComponent(key)}`;

  const creditsUrl =
    `https://api.themoviedb.org/3/movie/${encodeURIComponent(
      tmdbId
    )}/credits?api_key=${encodeURIComponent(key)}`;

  const [movieResponse, creditsResponse] =
    await Promise.all([
      fetch(movieUrl),
      fetch(creditsUrl)
    ]);

  if (!movieResponse.ok) {
    throw new Error("TMDB movie not found");
  }

  if (!creditsResponse.ok) {
    throw new Error("TMDB credits request failed");
  }

  const movie = await movieResponse.json();
  const credits = await creditsResponse.json();

  return {
    movie,
    credits
  };
}

function runFFprobe(buffer) {
  return new Promise((resolve, reject) => {
    const ffprobePath =
      process.env.FFPROBE_PATH || "ffprobe";

    const args = [
      "-v",
      "error",
      "-show_entries",
      "format=duration",
      "-of",
      "default=noprint_wrappers=1:nokey=1",
      "-"
    ];

    const process = spawn(ffprobePath, args);

    let output = "";
    let errorOutput = "";

    process.stdout.on("data", data => {
      output += data.toString();
    });

    process.stderr.on("data", data => {
      errorOutput += data.toString();
    });

    process.on("error", error => {
      reject(error);
    });

    process.on("close", code => {
      if (code !== 0) {
        return reject(
          new Error(
            `FFprobe failed: ${errorOutput || "unknown error"}`
          )
        );
      }

      const duration = Number(output.trim());

      if (!Number.isFinite(duration) || duration <= 0) {
        return reject(
          new Error("Unable to determine video duration")
        );
      }

      resolve(duration);
    });

    process.stdin.write(buffer);
    process.stdin.end();
  });
}

/* ---------------- HEALTH ---------------- */

app.get("/api/health", async (req, res) => {
  try {
    await query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      database: "disconnected",
      message: error.message
    });
  }
});

/* ---------------- AUTH ---------------- */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      email,
      password,
      displayName
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const existing = await query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existing.rowCount > 0) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    const passwordHash = await bcrypt.hash(
      password,
      12
    );

    const result = await query(
      `
      INSERT INTO users
        (email, password_hash, display_name)
      VALUES
        ($1, $2, $3)
      RETURNING
        id,
        email,
        display_name,
        role,
        download_credits,
        created_at
      `,
      [
        normalizedEmail,
        passwordHash,
        displayName || null
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      user,
      token: createToken(user)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const result = await query(
      `
      SELECT
        id,
        email,
        password_hash,
        display_name,
        role,
        download_credits,
        created_at
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    delete user.password_hash;

    res.json({
      user,
      token: createToken(user)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await query(
      `
      SELECT
        id,
        email,
        display_name,
        role,
        download_credits,
        created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    res.json({
      user: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      error: "Unable to load profile"
    });
  }
});

/* ---------------- TMDB ---------------- */

app.get("/api/tmdb/search", auth, requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();

    if (!q) {
      return res.status(400).json({
        error: "Search query required"
      });
    }

    const key = process.env.TMDB_API_KEY;

    if (!key) {
      return res.status(500).json({
        error: "TMDB API key not configured"
      });
    }

    const url =
      `https://api.themoviedb.org/3/search/movie` +
      `?api_key=${encodeURIComponent(key)}` +
      `&query=${encodeURIComponent(q)}` +
      `&include_adult=false`;

    const response = await fetch(url);

    if (!response.ok) {
      throw new Error("TMDB search failed");
    }

    const data = await response.json();

    res.json(data);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "TMDB search failed"
    });
  }
});

app.get(
  "/api/tmdb/movie/:id",
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const data = await getTmdbMovie(
        req.params.id
      );

      res.json({
        movie: data.movie,
        credits: data.credits
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ---------------- MOVIE UPLOAD ---------------- */

app.post(
  "/api/admin/movies/upload",
  auth,
  requireAdmin,
  upload.single("video"),
  async (req, res) => {
    try {
      const {
        tmdbId,
        muxPlaybackId
      } = req.body;

      if (!tmdbId) {
        return res.status(400).json({
          error: "tmdbId is required"
        });
      }

      if (!muxPlaybackId) {
        return res.status(400).json({
          error: "muxPlaybackId is required"
        });
      }

      if (!req.file) {
        return res.status(400).json({
          error: "Movie video file is required"
        });
      }

      const {
        movie,
        credits
      } = await getTmdbMovie(tmdbId);

      if (!movie.runtime) {
        return res.status(400).json({
          error: "TMDB runtime is unavailable"
        });
      }

      if (
        movie.runtime <
        MIN_RUNTIME_MINUTES
      ) {
        return res.status(400).json({
          error:
            `Movie runtime must be at least ${MIN_RUNTIME_MINUTES} minutes`
        });
      }

      let actualDuration;

      try {
        actualDuration =
          await runFFprobe(req.file.buffer);
      } catch (error) {
        console.error(error);

        return res.status(400).json({
          error:
            "Unable to verify uploaded video duration. Make sure FFprobe/FFmpeg is installed."
        });
      }

      const actualMinutes =
        actualDuration / 60;

      const difference =
        Math.abs(
          actualMinutes - movie.runtime
        );

      if (
        difference >
        RUNTIME_TOLERANCE_MINUTES
      ) {
        return res.status(400).json({
          error:
            `Video duration does not match TMDB runtime. TMDB: ${movie.runtime} min. Uploaded: ${actualMinutes.toFixed(1)} min.`
        });
      }

      const posterPath =
        movie.poster_path
          ? `https://image.tmdb.org/t/p/w500${movie.poster_path}`
          : null;

      const backdropPath =
        movie.backdrop_path
          ? `https://image.tmdb.org/t/p/original${movie.backdrop_path}`
          : null;

      const cast = (credits.cast || [])
        .slice(0, 20)
        .map(person => ({
          id: person.id,
          name: person.name,
          character: person.character,
          profile_path:
            person.profile_path
              ? `https://image.tmdb.org/t/p/w185${person.profile_path}`
              : null
        }));

      const genres =
        (movie.genres || []).map(
          genre => genre.name
        );

      const result = await query(
        `
        INSERT INTO movies
        (
          tmdb_id,
          title,
          overview,
          release_date,
          poster_path,
          backdrop_path,
          runtime_minutes,
          tmdb_rating,
          genres,
          cast_json,
          mux_playback_id,
          status,
          uploaded_by
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          $10,
          $11,
          'published',
          $12
        )
        ON CONFLICT (tmdb_id)
        DO UPDATE SET
          title = EXCLUDED.title,
          overview = EXCLUDED.overview,
          release_date = EXCLUDED.release_date,
          poster_path = EXCLUDED.poster_path,
          backdrop_path = EXCLUDED.backdrop_path,
          runtime_minutes = EXCLUDED.runtime_minutes,
          tmdb_rating = EXCLUDED.tmdb_rating,
          genres = EXCLUDED.genres,
          cast_json = EXCLUDED.cast_json,
          mux_playback_id = EXCLUDED.mux_playback_id,
          status = 'published'
        RETURNING *
        `,
        [
          movie.id,
          movie.title,
          movie.overview || "",
          movie.release_date || null,
          posterPath,
          backdropPath,
          movie.runtime,
          movie.vote_average || 0,
          genres,
          JSON.stringify(cast),
          muxPlaybackId,
          req.user.id
        ]
      );

      res.status(201).json({
        message: "Movie uploaded successfully",
        movie: result.rows[0],
        actual_duration_minutes:
          Number(actualMinutes.toFixed(2)),
        tmdb_runtime_minutes:
          movie.runtime
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          error.message ||
          "Movie upload failed"
      });
    }
  }
);

/* ---------------- MOVIES ---------------- */

app.get("/api/movies", async (req, res) => {
  try {
    const {
      search,
      genre,
      limit = 50,
      offset = 0
    } = req.query;

    const values = [];
    const conditions = [
      "status = 'published'"
    ];

    if (search) {
      values.push(
        `%${String(search).trim()}%`
      );

      conditions.push(
        `title ILIKE $${values.length}`
      );
    }

    if (genre) {
      values.push(genre);

      conditions.push(
        `$${values.length} = ANY(genres)`
      );
    }

    values.push(
      Math.min(Number(limit) || 50, 100)
    );

    const limitIndex = values.length;

    values.push(
      Math.max(Number(offset) || 0, 0)
    );

    const offsetIndex = values.length;

    const result = await query(
      `
      SELECT *
      FROM movies
      WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC
      LIMIT $${limitIndex}
      OFFSET $${offsetIndex}
      `,
      values
    );

    res.json({
      movies: result.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load movies"
    });
  }
});

app.get("/api/movies/:id", async (req, res) => {
  try {
    const result = await query(
      `
      SELECT *
      FROM movies
      WHERE id = $1
      AND status = 'published'
      `,
      [req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "Movie not found"
      });
    }

    res.json({
      movie: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      error: "Unable to load movie"
    });
  }
});

/* ---------------- TRENDING ---------------- */

app.get("/api/trending", async (req, res) => {
  try {
    const result = await query(
      `
      SELECT m.*
      FROM trending_movies t
      JOIN movies m
        ON m.id = t.movie_id
      WHERE m.status = 'published'
      ORDER BY t.position ASC
      `
    );

    res.json({
      movies: result.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load trending movies"
    });
  }
});

app.post(
  "/api/admin/trending",
  auth,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const {
        movieId,
        position = 1
      } = req.body;

      if (!movieId) {
        return res.status(400).json({
          error: "movieId is required"
        });
      }

      const movie = await query(
        `
        SELECT id
        FROM movies
        WHERE id = $1
        AND status = 'published'
        `,
        [movieId]
      );

      if (movie.rowCount === 0) {
        return res.status(404).json({
          error: "Published movie not found"
        });
      }

      const result = await query(
        `
        INSERT INTO trending_movies
          (movie_id, position, added_by)
        VALUES
          ($1, $2, $3)
        ON CONFLICT (movie_id)
        DO UPDATE SET
          position = EXCLUDED.position
        RETURNING *
        `,
        [
          movieId,
          Number(position),
          req.user.id
        ]
      );

      res.json({
        trending: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to update trending"
      });
    }
  }
);

app.delete(
  "/api/admin/trending/:movieId",
  auth,
  requireSuperAdmin,
  async (req, res) => {
    try {
      await query(
        `
        DELETE FROM trending_movies
        WHERE movie_id = $1
        `,
        [req.params.movieId]
      );

      res.json({
        message:
          "Movie removed from trending"
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Unable to remove trending movie"
      });
    }
  }
);

/* ---------------- ADMIN MOVIES ---------------- */

app.get(
  "/api/admin/movies",
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT *
        FROM movies
        ORDER BY created_at DESC
        `
      );

      res.json({
        movies: result.rows
      });
    } catch (error) {
      res.status(500).json({
        error: "Unable to load admin movies"
      });
    }
  }
);

app.delete(
  "/api/admin/movies/:id",
  auth,
  requireSuperAdmin,
  async (req, res) => {
    try {
      await query(
        `
        UPDATE movies
        SET status = 'deleted'
        WHERE id = $1
        `,
        [req.params.id]
      );

      res.json({
        message: "Movie deleted"
      });
    } catch (error) {
      res.status(500).json({
        error: "Unable to delete movie"
      });
    }
  }
);

/* ---------------- DOWNLOADS ---------------- */

app.post(
  "/api/download/authorize",
  auth,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const {
        movieId
      } = req.body;

      if (!movieId) {
        return res.status(400).json({
          error: "movieId is required"
        });
      }

      await client.query("BEGIN");

      const userResult =
        await client.query(
          `
          SELECT
            id,
            created_at,
            download_credits
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [req.user.id]
        );

      if (userResult.rowCount === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "User not found"
        });
      }

      const movieResult =
        await client.query(
          `
          SELECT id, mux_playback_id
          FROM movies
          WHERE id = $1
          AND status = 'published'
          `,
          [movieId]
        );

      if (movieResult.rowCount === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Movie not found"
        });
      }

      const user = userResult.rows[0];

      const freeUntil =
        new Date(user.created_at).getTime() +
        24 * 60 * 60 * 1000;

      const isFreePeriod =
        Date.now() < freeUntil;

      if (isFreePeriod) od =
        Date.now() < freeUntil;

      if (isFreePeriod) {
        await client.query(
          `
          INSERT INTO downloads
          (
            user_id,
            movie_id,
            used_free_period,
            credits_spent
          )
          VALUES
          ($1, $2, true, 0)
          `,
          [
            req.user.id,
            movieId
          ]
        );

        await client.query("COMMIT");

        return res.json({
          authorized: true,
          free_period: true,
          credits_spent: 0,
          playback_id:
            movieResult.rows[0]
              .mux_playback_id
        });
      }

      if (
        Number(user.download_credits) < 1
      ) {
        await client.query("ROLLBACK");

        return res.status(402).json({
          authorized: false,
          error:
            "No download credits. Watch a rewarded ad or buy coins."
        });
      }

      await client.query(
        `
        UPDATE users
        SET download_credits =
          download_credits - 1
        WHERE id = $1
        `,
        [req.user.id]
      );

      await client.query(
        `
        INSERT INTO credit_ledger
        (
          user_id,
          kind,
          amount,
          reason
        )
        VALUES
        ($1, 'debit', 1, 'movie_download')
        `,
        [req.user.id]
      );

      await client.query(
        `
        INSERT INTO downloads
        (
          user_id,
          movie_id,
          used_free_period,
          credits_spent
        )
        VALUES
        ($1, $2, false, 1)
        `,
        [
          req.user.id,
          movieId
        ]
      );

      await client.query("COMMIT");

      res.json({
        authorized: true,
        free_period: false,
        credits_spent: 1,
        remaining_credits:
          Number(user.download_credits) - 1,
        playback_id:
          movieResult.rows[0]
            .mux_playback_id
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      res.status(500).json({
        error:
          "Unable to authorize download"
      });
    } finally {
      client.release();
    }
  }
);

/* ---------------- REWARDED ADS ---------------- */

app.post(
  "/api/rewards/grant",
  auth,
  async (req, res) => {
    try {
      const {
        rewardId,
        signature
      } = req.body;

      if (!rewardId || !signature) {
        return res.status(400).json({
          error:
            "rewardId and signature are required"
        });
      }

      const secret =
        process.env.REWARD_WEBHOOK_SECRET;

      if (!secret) {
        return res.status(500).json({
          error:
            "Reward system is not configured"
        });
      }

      const expected =
        crypto
          .createHmac("sha256", secret)
          .update(
            `${req.user.id}:${rewardId}`
          )
          .digest("hex");

      if (
        !crypto.timingSafeEqual(
          Buffer.from(signature),
          Buffer.from(expected)
        )
      ) {
        return res.status(403).json({
          error: "Invalid reward signature"
        });
      }

      const existing =
        await query(
          `
          SELECT id
          FROM ad_rewards
          WHERE reward_id = $1
          `,
          [rewardId]
        );

      if (existing.rowCount > 0) {
        return res.json({
          message:
            "Reward already processed"
        });
      }

      await query("BEGIN");

      await query(
        `
        INSERT INTO ad_rewards
        (
          user_id,
          reward_id
        )
        VALUES
        ($1, $2)
        `,
        [
          req.user.id,
          rewardId
        ]
      );

      await query(
        `
        UPDATE users
        SET download_credits =
          download_credits + 5
        WHERE id = $1
        `,
        [req.user.id]
      );

      await query(
        `
        INSERT INTO credit_ledger
        (
          user_id,
          kind,
          amount,
          reason
        )
        VALUES
        ($1, 'credit', 5, 'rewarded_ad')
        `,
        [req.user.id]
      );

      await query("COMMIT");

      res.json({
        message:
          "5 download credits added",
        credits_added: 5
      });
    } catch (error) {
      try {
        await query("ROLLBACK");
      } catch {}

      console.error(error);

      res.status(500).json({
        error:
          "Unable to grant reward"
      });
    }
  }
);

/* ---------------- COINS ---------------- */

app.post(
  "/api/coins/credit",
  auth,
  async (req, res) => {
    res.status(405).json({
      error:
        "Coins must be credited by a verified payment webhook."
    });
  }
);

/* ---------------- 404 ---------------- */

app.use((req, res) => {
  res.status(404).json({
    error: "Route not found"
  });
});

/* ---------------- ERROR HANDLER ---------------- */

app.use((error, req, res, next) => {
  console.error(error);

  res.status(500).json({
    error: "Internal server error"
  });
});

/* ---------------- START ---------------- */

app.listen(
                    PORT,
                    "0.0.0.0",
                    () => {

                        console.log(
                            `ADAMOVIES backend running on port ${PORT}`
                        );

                        console.log(
                            "ADAMOVIES database schema: adamovies"
                        );

                    }
                );

            } catch (error) {

                console.error(
                    "FAILED TO START SERVER:",
                    error
                );

                process.exit(1);

            }

        }


        startServer();
});

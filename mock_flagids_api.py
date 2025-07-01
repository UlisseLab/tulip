from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI()

@app.get("/flagId")
def get_flagids():
    data = {
        "service1": {
            "1": {
                "20": {
                    "flagid1_desc": "flagid1_service1_team1_round20",
                    "flagid2_desc": "flagid2_service1_team1_round20"
                },
                "21": {
                    "flagid1_desc": "flagid1_service1_team1_round21"
                },
                "22": {
                    "flagid1_desc": "flagid1_service1_team1_round22"
                },
                "23": {
                    "flagid1_desc": "9cwlNUSI2zkC"
                },
                "24": {
                    "flagid1_desc": "flagid1_service1_team1_round24"
                }
            },
            "2": {
                "20": {
                    "flagid1_desc": "flagid1_service1_team2_round20"
                },
                "21": {
                    "flagid1_desc": "flagid1_service1_team2_round21"
                },
                "22": {
                    "flagid1_desc": "flagid1_service1_team2_round22"
                },
                "23": {
                    "flagid1_desc": "flagid1_service1_team2_round23"
                },
                "24": {
                    "flagid1_desc": "flagid1_service1_team2_round24"
                }
            }
        },
        "service2": {
            "1": {
                "20": {
                    "flagid1_desc": "user_resvBz"
                },
                "21": {
                    "flagid1_desc": "flagid1_service2_team1_round21"
                },
                "22": {
                    "flagid1_desc": "flagid1_service2_team1_round22"
                },
                "23": {
                    "flagid1_desc": "flagid1_service2_team1_round23"
                },
                "24": {
                    "flagid1_desc": "kenneth71"
                }
            },
            "2": {
                "20": {
                    "flagid1_desc": "EJ3ZK"
                },
                "21": {
                    "flagid1_desc": "flagid1_service2_team2_round21"
                },
                "22": {
                    "flagid1_desc": "flagid1_service2_team2_round22"
                },
                "23": {
                    "flagid1_desc": "flagid1_service2_team2_round23"
                },
                "24": {
                    "flagid1_desc": "kenneth71"
                }
            }
        },
        "service3": {
            "1": {
                "20": {
                    "flagid1_desc": "flagid1_service3_team1_round20"
                },
                "21": {
                    "flagid1_desc": "flagid1_service3_team1_round21"
                },
                "22": {
                    "flagid1_desc": "flagid1_service3_team1_round22"
                },
                "23": {
                    "flagid1_desc": "flagid1_service3_team1_round23"
                },
                "24": {
                    "flagid1_desc": "flagid1_service3_team1_round24"
                }
            },
            "2": {
                "20": {
                    "flagid1_desc": "flagid1_service3_team2_round20"
                },
                "21": {
                    "flagid1_desc": "flagid1_service3_team2_round21"
                },
                "22": {
                    "flagid1_desc": "flagid1_service3_team2_round22"
                },
                "23": {
                    "flagid1_desc": "flagid1_service3_team2_round23"
                },
                "24": {
                    "flagid1_desc": "flagid1_service3_team2_round24"
                }
            },
            "3": {
                "20": {
                    "flagid1_desc": "flagid1_service3_team3_round20"
                },
                "21": {
                    "flagid1_desc": "kenneth712"
                },
                "22": {
                    "flagid1_desc": "flagid1_service3_team3_round22"
                },
                "23": {
                    "flagid1_desc": "flagid1_service3_team3_round23"
                },
                "24": {
                    "flagid1_desc": "kenneth71"
                }
            }
        }
    }
    return JSONResponse(content=data)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
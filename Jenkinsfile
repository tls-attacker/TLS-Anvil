@Library('jenkins-ci-library@v2') _

standardPipeline(
    enableCentralRelease: true,
    publicRepoUrl: "https://github.com/tls-attacker/TLS-Anvil.git",
    extraStages: {
        // legacy stages
        //     gitHubRelease(
        //             nameApp: 'tlsanvil'
        //     )
        releaseDocker.LEGACY_dockerBuild(
            nameApp: 'tlsanvil',
            dockerfile: 'Dockerfile_dev'
        )
    }
)